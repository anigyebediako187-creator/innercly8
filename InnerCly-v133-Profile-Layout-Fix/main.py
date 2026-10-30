from __future__ import annotations

import base64
import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import threading
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Generator, Optional
from urllib.parse import quote, urlparse, urlencode
from urllib.request import Request as UrlRequest, urlopen
from urllib.error import HTTPError, URLError

from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, Boolean, Numeric, UniqueConstraint, create_engine, select, func, delete, or_, and_, desc, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker, relationship, load_only
from currency_registry import CURRENCIES, DEFAULT_BY_REGION

BASE_DIR = Path(__file__).resolve().parent
APP_ENV = os.getenv("APP_ENV", "production").strip().lower()
_raw_database_url = os.getenv("DATABASE_URL", "").strip()


def _readonly_sqlite_uri(path: Path) -> str:
    return "file:" + quote(path.resolve().as_posix(), safe="/:-") + "?mode=ro"


def _sqlite_user_count(path: Path) -> int:
    try:
        if not path.is_file():
            return -1
        uri = _readonly_sqlite_uri(path)
        with sqlite3.connect(uri, uri=True, timeout=2) as con:
            found = con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
            if not found:
                return -1
            return int(con.execute("SELECT COUNT(*) FROM users").fetchone()[0])
    except (sqlite3.Error, OSError, ValueError):
        return -1


def _previous_innercly_databases(current_db: Path) -> list[Path]:
    """Find prior local release databases without reading their account secrets into memory."""
    roots = [BASE_DIR.parent, Path.home() / "Downloads", Path.home() / "Desktop", Path.home() / "Documents"]
    candidates: dict[str, Path] = {}
    current_resolved = current_db.resolve()
    direct_candidate = BASE_DIR / "innercly_dev.db"
    direct_resolved = direct_candidate.resolve()
    if direct_resolved != current_resolved and direct_candidate.is_file() and _sqlite_user_count(direct_candidate) > 0:
        candidates[str(direct_resolved)] = direct_candidate
    for root in roots:
        try:
            if not root.is_dir():
                continue
            for folder in root.iterdir():
                if not folder.is_dir() or "innercly" not in folder.name.lower():
                    continue
                candidate = folder / "innercly_dev.db"
                try:
                    resolved = candidate.resolve()
                    if resolved == current_resolved or str(resolved) in candidates:
                        continue
                    if candidate.is_file() and _sqlite_user_count(candidate) > 0:
                        candidates[str(resolved)] = candidate
                except OSError:
                    continue
        except OSError:
            continue
    return sorted(candidates.values(), key=lambda item: item.stat().st_mtime, reverse=True)


def _shared_local_data_dir() -> Path:
    """Use one per-user data directory across all extracted local InnerCly versions."""
    custom = os.getenv("INNERCLY_LOCAL_DATA_DIR", "").strip()
    if custom:
        return Path(custom).expanduser().resolve()
    if os.name == "nt" and os.getenv("LOCALAPPDATA"):
        root = Path(os.environ["LOCALAPPDATA"]) / "InnerCly"
    elif os.getenv("XDG_DATA_HOME"):
        root = Path(os.environ["XDG_DATA_HOME"]) / "InnerCly"
    else:
        root = Path.home() / ".local" / "share" / "InnerCly"
    return root.expanduser().resolve()


def _sqlite_url_for(path: Path) -> str:
    # SQLAlchemy's sqlite URL for an absolute path, including Windows drive paths.
    return "sqlite:///" + path.resolve().as_posix()


def _adopt_existing_local_database(target_path: Path) -> None:
    """Seed the shared per-user database from an older release, without altering it."""
    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_users = _sqlite_user_count(target_path)
    if target_users > 0:
        return
    sources = _previous_innercly_databases(target_path)
    source_path = next((path for path in sources if path.resolve() != target_path.resolve() and _sqlite_user_count(path) > 0), None)
    if source_path is None:
        return
    backup_path = target_path.with_name("innercly_dev.pre-account-migration.db")
    try:
        if target_path.exists() and not backup_path.exists():
            shutil.copy2(target_path, backup_path)
        # Use SQLite's backup API while reading the source in read-only/query-only mode.
        source_uri = _readonly_sqlite_uri(source_path)
        with sqlite3.connect(source_uri, uri=True, timeout=15) as source:
            source.execute("PRAGMA query_only=ON")
            with sqlite3.connect(target_path, timeout=20) as destination:
                source.backup(destination)
        print(f"[InnerCly] Reused existing local account data from {source_path.parent.name}; the source file was left untouched.")
    except (sqlite3.Error, OSError) as exc:
        print(f"[InnerCly] Prior local database was not imported ({exc}). Original files were kept.")


if not _raw_database_url:
    if APP_ENV != "development":
        raise RuntimeError(
            "DATABASE_URL is required outside development. Set it to a PostgreSQL connection URL before deployment."
        )
    _shared_db_path = _shared_local_data_dir() / "innercly_dev.db"
    _adopt_existing_local_database(_shared_db_path)
    DATABASE_URL = _sqlite_url_for(_shared_db_path)
elif _raw_database_url.startswith("postgres://"):
    DATABASE_URL = "postgresql+psycopg://" + _raw_database_url.removeprefix("postgres://")
elif _raw_database_url.startswith("postgresql://"):
    DATABASE_URL = "postgresql+psycopg://" + _raw_database_url.removeprefix("postgresql://")
else:
    DATABASE_URL = _raw_database_url

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, pool_pre_ping=True, connect_args=connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)
SESSION_COOKIE = "innercly_session"
SESSION_LIFETIME = timedelta(days=30)
MAX_AVATAR_CHARS = 300_000
USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{3,32}$")
# Owner bootstrap is tied to the configured InnerCly username, never to a browser flag. Default owner username: innercly_owner.
OWNER_USERNAME = os.getenv("INNERCLY_OWNER_USERNAME", "innercly_owner").strip().lstrip("@").lower() or "innercly_owner"
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "").strip()
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "").strip()
# InnerCly pricing policy: $4.99 monthly / $49 annual / $149 lifetime.
# The first 500 founding lifetime passes are $99; checkout enforces the cap server-side.
PREMIUM_PLAN_PRICES = {"monthly": Decimal("4.99"), "annual": Decimal("49.00"), "lifetime": Decimal("149.00"), "founding_lifetime": Decimal("99.00")}
PREMIUM_PLAN_DAYS = {"monthly": 30, "annual": 365, "lifetime": None, "founding_lifetime": None}
LIFETIME_PLAN_CODES = {"lifetime", "founding_lifetime"}
FOUNDING_MEMBER_LIMIT = 500
LIFETIME_STORAGE_CAP_BYTES = 50 * 1024 * 1024 * 1024
# Owner can explicitly enroll creator accounts in the Early Adopter or exclusive-hub programs via service env vars.
EARLY_ADOPTER_USERNAMES = {x.strip().lstrip("@").lower() for x in os.getenv("INNERCLY_EARLY_ADOPTER_USERNAMES", "").split(",") if x.strip()}
EXCLUSIVE_SUBSCRIPTION_HUB_USERNAMES = {x.strip().lstrip("@").lower() for x in os.getenv("INNERCLY_EXCLUSIVE_SUBSCRIPTION_HUB_USERNAMES", "").split(",") if x.strip()}
# Kilos are virtual credits. Pack prices are configurable in code before checkout is enabled.
KILOS_PACKS = {
    "starter": {"kilos": 1000, "price": Decimal("1.99"), "label": "Starter"},
    "creator": {"kilos": 5500, "price": Decimal("7.99"), "label": "Creator"},
    "supporter": {"kilos": 12000, "price": Decimal("14.99"), "label": "Supporter"},
}
KILOS_FACE_VALUE_USD_PER_1000 = Decimal("1.00")
KILOS_CREATOR_SHARE = Decimal("0.80")
EARLY_ADOPTER_CREATOR_SHARE = Decimal("0.90")
AD_CREATOR_SHARE = Decimal("0.55")
DIGITAL_MARKETPLACE_COMMISSION_RATE = Decimal("0.10")
PHYSICAL_MARKETPLACE_COMMISSION_RATE = Decimal("0.05")
ASSIGNABLE_ROLES = {"member", "creator", "moderator", "administrator"}
ROLE_DESCRIPTIONS = {
    "member": "Standard access to everyday InnerCly features.",
    "creator": "Creator status for creator-focused features as they are enabled.",
    "moderator": "Trusted community moderation role; restricted tools are enabled only through server permission checks.",
    "administrator": "Platform administration role; does not grant Owner or role-management access.",
    "owner": "Full owner control, including granting and removing other roles.",
}


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(32), unique=True, index=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(48), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    avatar_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    bio: Mapped[str] = mapped_column(String(280), default="", server_default="", nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="member", server_default="member", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    sessions: Mapped[list["AuthSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    account_badges: Mapped[list["RtAccountBadge"]] = relationship(back_populates="user", cascade="all, delete-orphan", foreign_keys="RtAccountBadge.user_id")
    premium_subscription: Mapped[Optional["RtPremiumSubscription"]] = relationship(back_populates="user", uselist=False, cascade="all, delete-orphan")



# Case-insensitive username uniqueness; startup migration checks legacy duplicates first.
Index("uq_users_username_lower", func.lower(User.username), unique=True)

class AuthSession(Base):
    __tablename__ = "auth_sessions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)
    user: Mapped[User] = relationship(back_populates="sessions")


class RtAccountBadge(Base):
    __tablename__ = "rt_account_badges"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    badge_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true", nullable=False)
    reason: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    granted_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    user: Mapped[User] = relationship(back_populates="account_badges", foreign_keys=[user_id])
    __table_args__ = (UniqueConstraint("user_id", "badge_type", name="uq_rt_account_badge_user_type"),)


class RtBadgeAudit(Base):
    __tablename__ = "rt_badge_audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    target_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    badge_type: Mapped[str] = mapped_column(String(16), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False)
    reason: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)


class RtVerifiedCreatorInvite(Base):
    __tablename__ = "rt_verified_creator_invites"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)
    invited_by: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class FailedLogin(Base):
    __tablename__ = "failed_logins"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ip_fingerprint: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, default=lambda: datetime.now(timezone.utc), nullable=False)


Index("ix_failed_login_ip_time", FailedLogin.ip_fingerprint, FailedLogin.attempted_at)



# Real-time social features, including friend-only 24-hour Stories.
class RtPost(Base):
    __tablename__ = "rt_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    text: Mapped[str] = mapped_column(Text, default="", nullable=False)
    media_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    media_type: Mapped[str] = mapped_column(String(20), default="", nullable=False)
    visibility: Mapped[str] = mapped_column(String(12), default="public", nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

class RtVerifiedCreatorPost(Base):
    __tablename__ = "rt_verified_creator_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    text: Mapped[str] = mapped_column(Text, default="", nullable=False)
    media_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    media_type: Mapped[str] = mapped_column(String(20), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)


class RtPostLike(Base):
    __tablename__ = "rt_post_likes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    post_id: Mapped[int] = mapped_column(ForeignKey("rt_posts.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("post_id", "user_id", name="uq_rt_post_like"),)

class RtPostComment(Base):
    __tablename__ = "rt_post_comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    post_id: Mapped[int] = mapped_column(ForeignKey("rt_posts.id", ondelete="CASCADE"), index=True, nullable=False)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    parent_comment_id: Mapped[Optional[int]] = mapped_column(ForeignKey("rt_post_comments.id", ondelete="CASCADE"), index=True, nullable=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

class RtFriendRequest(Base):
    __tablename__ = "rt_friend_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    receiver_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

class RtFriendship(Base):
    __tablename__ = "rt_friendships"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_a_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    user_b_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("user_a_id", "user_b_id", name="uq_rt_friendship_pair"),)

class RtUserFollow(Base):
    __tablename__ = "rt_user_follows"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    follower_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    following_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("follower_id", "following_id", name="uq_rt_user_follow_pair"),)

class RtRoleAudit(Base):
    __tablename__ = "rt_role_audit"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    target_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    old_role: Mapped[str] = mapped_column(String(20), nullable=False)
    new_role: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

class RtDirectMessage(Base):
    __tablename__ = "rt_direct_messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    recipient_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    media_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reply_to_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    edited_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

class RtGroup(Base):
    __tablename__ = "rt_groups"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    description: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    visibility: Mapped[str] = mapped_column(String(12), default="Public", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

class RtGroupMember(Base):
    __tablename__ = "rt_group_members"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("rt_groups.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    role: Mapped[str] = mapped_column(String(12), default="member", nullable=False)
    joined_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("group_id", "user_id", name="uq_rt_group_member"),)

class RtGroupMessage(Base):
    __tablename__ = "rt_group_messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("rt_groups.id", ondelete="CASCADE"), index=True, nullable=False)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    text: Mapped[str] = mapped_column(Text, default="", nullable=False)
    attachment_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    reply_to_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    edited_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

class RtListing(Base):
    __tablename__ = "rt_market_listings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    seller_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(120), nullable=False)
    category: Mapped[str] = mapped_column(String(32), default="General", nullable=False, index=True)
    listing_type: Mapped[str] = mapped_column(String(16), default="physical", nullable=False, index=True)
    # `price` remains for legacy free-text listings; new listings use amount + ISO 4217 code.
    price: Mapped[str] = mapped_column(String(80), nullable=False)
    price_amount: Mapped[Optional[Decimal]] = mapped_column(Numeric(20, 6), nullable=True)
    currency_code: Mapped[Optional[str]] = mapped_column(String(3), nullable=True, index=True)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    image_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="For sale", nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

class RtMarketConversation(Base):
    __tablename__ = "rt_market_conversations"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    listing_id: Mapped[int] = mapped_column(ForeignKey("rt_market_listings.id", ondelete="CASCADE"), index=True, nullable=False)
    buyer_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    seller_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("listing_id", "buyer_id", name="uq_rt_market_conversation"),)

class RtMarketMessage(Base):
    __tablename__ = "rt_market_messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    conversation_id: Mapped[int] = mapped_column(ForeignKey("rt_market_conversations.id", ondelete="CASCADE"), index=True, nullable=False)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

class RtDelivery(Base):
    __tablename__ = "rt_market_deliveries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    listing_id: Mapped[int] = mapped_column(ForeignKey("rt_market_listings.id", ondelete="CASCADE"), index=True, nullable=False)
    buyer_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    seller_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    phone: Mapped[str] = mapped_column(String(64), nullable=False)
    address: Mapped[str] = mapped_column(Text, nullable=False)
    note: Mapped[str] = mapped_column(Text, default="", nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="Requested", nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

class RtDeliveryMessage(Base):
    __tablename__ = "rt_market_delivery_messages"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    delivery_id: Mapped[int] = mapped_column(ForeignKey("rt_market_deliveries.id", ondelete="CASCADE"), index=True, nullable=False)
    sender_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    text: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

class RtCommunityRecord(Base):
    __tablename__ = "rt_community_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), index=True, nullable=False)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(120), nullable=False)
    body: Mapped[str] = mapped_column(Text, default="", nullable=False)
    extra_json: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

class RtCommunityFollow(Base):
    __tablename__ = "rt_community_follows"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    record_id: Mapped[int] = mapped_column(ForeignKey("rt_community_records.id", ondelete="CASCADE"), index=True, nullable=False)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("record_id", "user_id", name="uq_rt_community_follow"),)

class RtSavedItem(Base):
    __tablename__ = "rt_saved_items"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    resource_type: Mapped[str] = mapped_column(String(16), nullable=False)
    resource_id: Mapped[int] = mapped_column(Integer, nullable=False)
    collection_name: Mapped[str] = mapped_column(String(64), default="Saved", nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("user_id", "resource_type", "resource_id", name="uq_rt_saved_item"),)

class RtNotification(Base):
    __tablename__ = "rt_notifications"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    text: Mapped[str] = mapped_column(String(500), nullable=False)
    link_type: Mapped[str] = mapped_column(String(24), default="", nullable=False)
    link_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

class RtPremiumSubscription(Base):
    __tablename__ = "rt_premium_subscriptions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)
    plan_code: Mapped[str] = mapped_column(String(24), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="active", nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    stripe_checkout_session_id: Mapped[Optional[str]] = mapped_column(String(180), unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    user: Mapped["User"] = relationship(back_populates="premium_subscription")


class RtPremiumPreferences(Base):
    __tablename__ = "rt_premium_preferences"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)
    profile_theme: Mapped[str] = mapped_column(String(20), default="ice", nullable=False)
    story_effect: Mapped[str] = mapped_column(String(20), default="normal", nullable=False)
    chat_theme: Mapped[str] = mapped_column(String(20), default="ice", nullable=False)
    early_access_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class RtKilosWallet(Base):
    __tablename__ = "rt_kilos_wallets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)
    balance: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class RtKilosLedger(Base):
    __tablename__ = "rt_kilos_ledger"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    related_user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    transaction_type: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    delta_kilos: Mapped[int] = mapped_column(Integer, nullable=False)
    balance_after: Mapped[int] = mapped_column(Integer, nullable=False)
    reference_type: Mapped[str] = mapped_column(String(24), default="", nullable=False)
    reference_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    note: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)


class RtCheckoutPayment(Base):
    __tablename__ = "rt_checkout_payments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    payment_kind: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    product_key: Mapped[str] = mapped_column(String(32), nullable=False)
    amount_usd: Mapped[Decimal] = mapped_column(Numeric(12, 2), nullable=False)
    kilos_quantity: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    listing_id: Mapped[Optional[int]] = mapped_column(ForeignKey("rt_market_listings.id", ondelete="SET NULL"), index=True, nullable=True)
    seller_user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    currency_code: Mapped[str] = mapped_column(String(3), default="USD", nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False, index=True)
    stripe_checkout_session_id: Mapped[Optional[str]] = mapped_column(String(180), unique=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    paid_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class RtCreatorWallet(Base):
    __tablename__ = "rt_creator_wallets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), unique=True, index=True, nullable=False)
    available_usd: Mapped[Decimal] = mapped_column(Numeric(14, 2), default=Decimal("0.00"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class RtMonetizationRecord(Base):
    __tablename__ = "rt_monetization_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    record_type: Mapped[str] = mapped_column(String(28), nullable=False, index=True)
    actor_user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    creator_user_id: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), index=True, nullable=True)
    gross_amount_usd: Mapped[Decimal] = mapped_column(Numeric(14, 2), default=Decimal("0.00"), nullable=False)
    processing_fee_usd: Mapped[Decimal] = mapped_column(Numeric(14, 2), default=Decimal("0.00"), nullable=False)
    platform_commission_usd: Mapped[Decimal] = mapped_column(Numeric(14, 2), default=Decimal("0.00"), nullable=False)
    creator_amount_usd: Mapped[Decimal] = mapped_column(Numeric(14, 2), default=Decimal("0.00"), nullable=False)
    currency_code: Mapped[str] = mapped_column(String(3), default="USD", nullable=False)
    reference: Mapped[str] = mapped_column(String(180), default="", nullable=False)
    note: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)


class RtCreatorPayoutRequest(Base):
    __tablename__ = "rt_creator_payout_requests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    creator_user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    amount_usd: Mapped[Decimal] = mapped_column(Numeric(14, 2), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False, index=True)
    reviewed_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    payout_note: Mapped[str] = mapped_column(String(500), default="", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)


class RtLiveStream(Base):
    __tablename__ = "rt_live_streams"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    title: Mapped[str] = mapped_column(String(120), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="live", nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    show_in_feed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class RtUserBlock(Base):
    __tablename__ = "rt_user_blocks"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    blocker_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    blocked_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("blocker_id", "blocked_id", name="uq_rt_user_block_pair"),)

class RtUserMute(Base):
    __tablename__ = "rt_user_mutes"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    muter_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    muted_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("muter_id", "muted_id", name="uq_rt_user_mute_pair"),)

class RtContentReport(Base):
    __tablename__ = "rt_content_reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    reporter_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    target_type: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    target_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="pending", nullable=False, index=True)
    reviewed_by: Mapped[Optional[int]] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

class RtPostView(Base):
    __tablename__ = "rt_post_views"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    post_id: Mapped[int] = mapped_column(ForeignKey("rt_posts.id", ondelete="CASCADE"), index=True, nullable=False)
    viewer_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    view_date: Mapped[str] = mapped_column(String(10), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("post_id", "viewer_id", "view_date", name="uq_rt_post_view_daily"),)

class RtMessageReaction(Base):
    __tablename__ = "rt_message_reactions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    message_type: Mapped[str] = mapped_column(String(12), nullable=False, index=True)
    message_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    emoji: Mapped[str] = mapped_column(String(8), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("message_type", "message_id", "user_id", name="uq_rt_message_reaction_user"),)


class RtMediaAsset(Base):
    __tablename__ = "rt_media_assets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    filename: Mapped[str] = mapped_column(String(180), nullable=False)
    media_type: Mapped[str] = mapped_column(String(64), nullable=False)
    data_url: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)


class RtStory(Base):
    __tablename__ = "rt_stories"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False)
    text: Mapped[str] = mapped_column(Text, default="", nullable=False)
    media_data: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    media_type: Mapped[str] = mapped_column(String(12), default="text", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True, nullable=False)

class RegisterBody(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    display_name: str = Field(min_length=2, max_length=48)
    password: str = Field(min_length=12, max_length=128)
    avatar_data: Optional[str] = Field(default=None, max_length=MAX_AVATAR_CHARS)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        value = value.lower().strip()
        if not USERNAME_RE.fullmatch(value):
            raise ValueError("Use 3–32 letters, numbers, dots, underscores, or hyphens for your username.")
        return value

    @field_validator("display_name")
    @classmethod
    def valid_display_name(cls, value: str) -> str:
        if len(value.strip()) < 2:
            raise ValueError("Enter a display name with at least 2 characters.")
        return value.strip()

    @field_validator("avatar_data")
    @classmethod
    def validate_avatar(cls, value: Optional[str]) -> Optional[str]:
        if value is None or value == "":
            return None
        if not value.startswith(("data:image/jpeg;base64,", "data:image/png;base64,", "data:image/webp;base64,")):
            raise ValueError("Profile pictures must be JPEG, PNG, or WebP images.")
        if len(value) > MAX_AVATAR_CHARS:
            raise ValueError("That profile picture is too large. Choose a smaller image.")
        return value


class LoginBody(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("username")
    @classmethod
    def normalize_username(cls, value: str) -> str:
        value = value.lower().strip()
        if not USERNAME_RE.fullmatch(value):
            raise ValueError("Enter a valid InnerCly username.")
        return value



class RoleUpdateBody(BaseModel):
    role: str = Field(min_length=1, max_length=20)

    @field_validator("role")
    @classmethod
    def valid_role(cls, value: str) -> str:
        value = value.strip().lower()
        if value not in ASSIGNABLE_ROLES:
            raise ValueError("Choose Member, Creator, Moderator, or Administrator. Owner access cannot be assigned from this form.")
        return value


class ProfileUpdateBody(BaseModel):
    display_name: str = Field(min_length=2, max_length=48)
    username: Optional[str] = Field(default=None, min_length=3, max_length=32)
    bio: str = Field(default="", max_length=280)
    avatar_data: Optional[str] = Field(default=None, max_length=MAX_AVATAR_CHARS)

    @field_validator("display_name")
    @classmethod
    def profile_name_valid(cls, value: str) -> str:
        value = value.strip()
        if len(value) < 2:
            raise ValueError("Enter a display name with at least 2 characters.")
        return value

    @field_validator("username")
    @classmethod
    def profile_username_valid(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        value = value.strip().lstrip("@").lower()
        if not USERNAME_RE.fullmatch(value):
            raise ValueError("Choose a valid InnerCly username.")
        return value

    @field_validator("bio")
    @classmethod
    def profile_bio_valid(cls, value: str) -> str:
        return value.strip()[:280]

    @field_validator("avatar_data")
    @classmethod
    def profile_avatar_valid(cls, value: Optional[str]) -> Optional[str]:
        if value is None or value == "":
            return None
        if not value.startswith(("data:image/jpeg;base64,", "data:image/png;base64,", "data:image/webp;base64,")):
            raise ValueError("Profile pictures must be JPEG, PNG, or WebP images.")
        return value

class RtPostBody(BaseModel):
    text: str = Field(default="", max_length=5000)
    media_data: Optional[str] = Field(default=None, max_length=72_000_000)
    media_type: str = Field(default="", max_length=20)
    visibility: str = Field(default="public", pattern="^(public|friends)$")

class RtCommentBody(BaseModel):
    text: str = Field(min_length=1, max_length=2000)
    parent_comment_id: Optional[int] = Field(default=None, ge=1)

class RtFriendRequestBody(BaseModel):
    username: str = Field(min_length=3, max_length=32)

class RtMessageBody(BaseModel):
    text: str = Field(default="", max_length=4000)
    media_data: Optional[str] = Field(default=None, max_length=1_500_000)
    reply_to_id: Optional[int] = Field(default=None, ge=1)

class RtBlockBody(BaseModel):
    username: str = Field(min_length=3, max_length=32)

class RtReportBody(BaseModel):
    target_type: str = Field(pattern="^(post|user)$")
    target_id: int = Field(gt=0)
    reason: str = Field(min_length=3, max_length=500)

class RtSavedCollectionBody(BaseModel):
    collection_name: str = Field(min_length=1, max_length=64)

class RtReactionBody(BaseModel):
    emoji: str = Field(min_length=1, max_length=8)

class RtMessageEditBody(BaseModel):
    text: str = Field(min_length=1, max_length=4000)

class RtReportStatusBody(BaseModel):
    status: str = Field(pattern="^(reviewed|dismissed|pending)$")

class RtGroupBody(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    description: str = Field(default="", max_length=500)
    visibility: str = Field(default="Public", max_length=12)

class RtGroupMessageBody(BaseModel):
    text: str = Field(default="", max_length=4000)
    attachment_data: Optional[str] = Field(default=None, max_length=1_500_000)
    reply_to_id: Optional[int] = Field(default=None, ge=1)

class RtListingBody(BaseModel):
    title: str = Field(min_length=2, max_length=120)
    category: str = Field(default="General", min_length=2, max_length=32)
    listing_type: str = Field(default="physical", pattern="^(digital|physical)$")
    # Backwards-compatible legacy free-text field. New UI submits structured amount + currency.
    price: str = Field(default="", max_length=80)
    price_amount: Optional[Decimal] = Field(default=None, gt=0, max_digits=18, decimal_places=6)
    currency_code: Optional[str] = Field(default=None, min_length=3, max_length=3)
    description: str = Field(default="", max_length=4000)
    image_data: Optional[str] = Field(default=None, max_length=1_500_000)

class RtDeliveryBody(BaseModel):
    phone: str = Field(min_length=3, max_length=64)
    address: str = Field(min_length=5, max_length=1000)
    note: str = Field(default="", max_length=1000)

class RtDeliveryStatusBody(BaseModel):
    status: str = Field(min_length=2, max_length=24)

class RtCommunityBody(BaseModel):
    title: str = Field(min_length=2, max_length=120)
    body: str = Field(default="", max_length=5000)
    extra: dict = Field(default_factory=dict)

class RtSavedBody(BaseModel):
    resource_type: str = Field(pattern="^(post|listing)$")
    resource_id: int = Field(gt=0)
    collection_name: str = Field(default="Saved", min_length=1, max_length=64)

class RtMediaBody(BaseModel):
    filename: str = Field(min_length=1, max_length=180)
    data_url: str = Field(min_length=30, max_length=600_000)


class RtStoryBody(BaseModel):
    text: str = Field(default="", max_length=1500)
    media_data: Optional[str] = Field(default=None, max_length=11_800_000)
    media_type: str = Field(default="text", pattern="^(text|photo|video)$")


class PremiumCheckoutBody(BaseModel):
    plan: str = Field(min_length=3, max_length=24)


class KilosCheckoutBody(BaseModel):
    pack: str = Field(min_length=3, max_length=32)


class PremiumPreferencesBody(BaseModel):
    profile_theme: str = Field(default="ice", max_length=20)
    story_effect: str = Field(default="normal", max_length=20)
    chat_theme: str = Field(default="ice", max_length=20)


class KilosGiftBody(BaseModel):
    creator_username: str = Field(min_length=3, max_length=32)
    kilos: int = Field(ge=100, le=1000000)
    stream_id: int = Field(gt=0)


class CreatorPayoutBody(BaseModel):
    amount_usd: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    payout_note: str = Field(default="", max_length=500)


class AdminAdRevenueBody(BaseModel):
    creator_username: str = Field(min_length=3, max_length=32)
    amount_usd: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    reference: str = Field(default="", max_length=180)
    note: str = Field(default="", max_length=500)


class AdminMarketplaceSaleBody(BaseModel):
    seller_username: str = Field(min_length=3, max_length=32)
    gross_amount_usd: Decimal = Field(gt=0, max_digits=12, decimal_places=2)
    processing_fee_usd: Decimal = Field(ge=0, max_digits=12, decimal_places=2)
    reference: str = Field(default="", max_length=180)
    note: str = Field(default="", max_length=500)

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    # PBKDF2-HMAC-SHA256 with 600,000 rounds; stored format includes its parameters
    # so hashes can be migrated to Argon2 later without storing plaintext passwords.
    salt = secrets.token_bytes(16)
    rounds = 600_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return f"pbkdf2_sha256${rounds}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, rounds_text, salt_hex, expected_hex = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        rounds = int(rounds_text)
        if rounds < 100_000 or rounds > 2_000_000:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt_hex), rounds)
        return hmac.compare_digest(digest.hex(), expected_hex)
    except (ValueError, TypeError):
        return False




def _current_sqlite_path() -> Optional[Path]:
    """Return the absolute SQLite path for this local build, if applicable."""
    prefix = "sqlite:///"
    if not DATABASE_URL.startswith(prefix):
        return None
    raw_path = DATABASE_URL[len(prefix):]
    path = Path(raw_path)
    if not path.is_absolute():
        path = BASE_DIR / path
    return path.resolve()


def _sqlite_table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
    return {str(row[0]) for row in rows}


def _quote_ident(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def _copy_previous_database_data(source_path: Path, target_path: Path, login_username: str, verified_hash: str) -> bool:
    """Safely merge an authenticated account's older local DB into the current DB.

    This runs only after the submitted password has been validated against the source
    version's hash. It backs up the target first, never edits the source, maps IDs
    across tables, avoids re-copying exact/unique rows, and creates a fresh session
    afterward. Session and failed-login rows from the old DB are deliberately omitted.
    """
    try:
        source_path = source_path.resolve()
        target_path = target_path.resolve()
        if source_path == target_path or not source_path.is_file() or not target_path.is_file():
            return False
        backup_path = target_path.with_name("innercly_dev.pre-login-recovery.db")
        if not backup_path.exists():
            shutil.copy2(target_path, backup_path)

        source_uri = _readonly_sqlite_uri(source_path)
        with sqlite3.connect(source_uri, uri=True, timeout=12) as source, sqlite3.connect(target_path, timeout=20) as target:
            source.row_factory = sqlite3.Row
            target.row_factory = sqlite3.Row
            source_tables = _sqlite_table_names(source)
            target_tables = _sqlite_table_names(target)
            if "users" not in source_tables or "users" not in target_tables:
                return False
            source_user_cols = {r[1] for r in source.execute("PRAGMA table_info(users)").fetchall()}
            if not {"id", "username", "password_hash"}.issubset(source_user_cols):
                return False

            # Models in the current build provide parent-before-child order. Only tables
            # shared by source and destination are considered so older schemas remain usable.
            ordered = [table.name for table in Base.metadata.sorted_tables if table.name in source_tables and table.name in target_tables]
            if "users" not in ordered:
                ordered.insert(0, "users")
            if "auth_sessions" not in ordered and "auth_sessions" in target_tables:
                pass
            skip_tables = {"auth_sessions", "failed_logins"}
            mappings: dict[str, dict[object, object]] = {}

            def table_cols(conn: sqlite3.Connection, table_name: str) -> list[str]:
                return [str(r[1]) for r in conn.execute(f"PRAGMA table_info({_quote_ident(table_name)})").fetchall()]

            def pk_cols(conn: sqlite3.Connection, table_name: str) -> list[str]:
                info = conn.execute(f"PRAGMA table_info({_quote_ident(table_name)})").fetchall()
                return [str(r[1]) for r in sorted((r for r in info if int(r[5] or 0) > 0), key=lambda r: int(r[5]))]

            def key_for(row, columns):
                vals = tuple(row[c] for c in columns)
                return vals[0] if len(vals) == 1 else vals

            def fetch_existing_by_username(username: str):
                return target.execute('SELECT * FROM "users" WHERE lower("username") = ?', (username.lower(),)).fetchone()

            def insert_row(table_name: str, values: dict[str, object], pk: list[str], source_key):
                # Don't force an integer id if it collides; let SQLite generate a new id
                # and record the source->destination mapping for dependent rows.
                use_values = dict(values)
                if len(pk) == 1 and pk[0] == "id":
                    source_id = use_values.get("id")
                    if source_id is not None:
                        occupied = target.execute(f'SELECT 1 FROM {_quote_ident(table_name)} WHERE "id"=?', (source_id,)).fetchone()
                        if occupied:
                            use_values.pop("id", None)
                columns = list(use_values)
                if not columns:
                    return None
                sql = f'INSERT INTO {_quote_ident(table_name)} (' + ",".join(_quote_ident(c) for c in columns) + ") VALUES (" + ",".join("?" for _ in columns) + ")"
                cursor = target.execute(sql, [use_values[c] for c in columns])
                if len(pk) == 1 and pk[0] == "id":
                    new_key = cursor.lastrowid
                else:
                    new_key = key_for(use_values, pk)
                return new_key

            def lookup_existing(table_name: str, values: dict[str, object], pk: list[str]):
                # First check any UNIQUE constraint/index, then exact content. This makes
                # repeat recovery idempotent and respects unique usernames/pairs.
                unique_sets = []
                for index_row in target.execute(f'PRAGMA index_list({_quote_ident(table_name)})').fetchall():
                    if int(index_row[2] or 0):
                        index_name = str(index_row[1])
                        cols = [str(x[2]) for x in target.execute(f'PRAGMA index_info({_quote_ident(index_name)})').fetchall()]
                        if cols and all(c in values for c in cols):
                            unique_sets.append(cols)
                for cols in unique_sets:
                    if any(values.get(c) is None for c in cols):
                        continue
                    where = " AND ".join(f'{_quote_ident(c)} IS ?' for c in cols)
                    found = target.execute(f'SELECT {",".join(_quote_ident(c) for c in pk)} FROM {_quote_ident(table_name)} WHERE {where} LIMIT 1', [values[c] for c in cols]).fetchone()
                    if found:
                        return key_for(found, pk)
                compare_cols = [c for c in values if c not in pk]
                if compare_cols:
                    where = " AND ".join(f'{_quote_ident(c)} IS ?' for c in compare_cols)
                    found = target.execute(f'SELECT {",".join(_quote_ident(c) for c in pk)} FROM {_quote_ident(table_name)} WHERE {where} LIMIT 1', [values[c] for c in compare_cols]).fetchone()
                    if found:
                        return key_for(found, pk)
                return None

            try:
                target.execute("PRAGMA foreign_keys=OFF")
                target.execute("BEGIN IMMEDIATE")
                # Users first so every other table can remap foreign keys safely.
                src_users = source.execute('SELECT * FROM "users" ORDER BY "id"').fetchall()
                destination_user_cols = set(table_cols(target, "users"))
                source_user_cols = set(table_cols(source, "users"))
                for src_user in src_users:
                    old_id = src_user["id"]
                    username = str(src_user["username"] or "").lower()
                    existing = fetch_existing_by_username(username)
                    if existing:
                        new_id = existing["id"]
                        # The user explicitly proved the source password. If this username
                        # exists in the current DB with a stale hash, update only its hash.
                        if username == login_username.lower() and str(src_user["password_hash"]) == verified_hash:
                            target.execute('UPDATE "users" SET "password_hash"=? WHERE "id"=?', (verified_hash, new_id))
                        mappings.setdefault("users", {})[old_id] = new_id
                        continue
                    vals = {c: src_user[c] for c in (source_user_cols & destination_user_cols) if c != "id"}
                    if "id" in destination_user_cols:
                        vals["id"] = old_id
                    try:
                        new_id = insert_row("users", vals, pk_cols(target, "users"), old_id)
                    except sqlite3.IntegrityError:
                        existing = fetch_existing_by_username(username)
                        if existing:
                            new_id = existing["id"]
                        else:
                            continue
                    if new_id is not None:
                        mappings.setdefault("users", {})[old_id] = new_id

                for table_name in ordered:
                    if table_name == "users" or table_name in skip_tables:
                        continue
                    src_cols = set(table_cols(source, table_name))
                    dest_cols = set(table_cols(target, table_name))
                    pk = pk_cols(target, table_name)
                    src_pk = pk_cols(source, table_name)
                    if not pk or not src_pk:
                        continue
                    fks = target.execute(f'PRAGMA foreign_key_list({_quote_ident(table_name)})').fetchall()
                    rows = source.execute(f'SELECT * FROM {_quote_ident(table_name)}').fetchall()
                    for src_row in rows:
                        try:
                            source_key = key_for(src_row, src_pk)
                            values = {c: src_row[c] for c in (src_cols & dest_cols)}
                            valid = True
                            for fk in fks:
                                col_name = str(fk[3]); parent_table = str(fk[2]); parent_col = str(fk[4])
                                if col_name not in values or values[col_name] is None:
                                    continue
                                parent_map = mappings.get(parent_table, {})
                                mapped_parent = parent_map.get(values[col_name])
                                if mapped_parent is None:
                                    # If the referenced table did not exist in the older DB,
                                    # skip orphaned rows rather than leave broken relations.
                                    valid = False; break
                                parent_table_pk = pk_cols(target, parent_table)
                                if len(parent_table_pk) == 1:
                                    values[col_name] = mapped_parent
                                else:
                                    if not isinstance(mapped_parent, tuple): valid = False; break
                                    values[col_name] = mapped_parent[parent_table_pk.index(parent_col)]
                            if not valid:
                                continue
                            table_model = Base.metadata.tables.get(table_name)
                            if table_model is not None:
                                for col in table_model.columns:
                                    if col.name in values or col.name in pk:
                                        continue
                                    if col.default is not None:
                                        default = col.default.arg
                                        try: values[col.name] = default() if callable(default) else default
                                        except Exception: pass
                            # If required newer columns are still absent, this legacy row
                            # isn't safe to import; leave it in the untouched source backup.
                            required_missing = any(
                                c.name not in values and c.name not in pk and not c.nullable and c.server_default is None and c.default is None
                                for c in table_model.columns
                            ) if table_model is not None else False
                            if required_missing:
                                continue
                            existing_key = lookup_existing(table_name, values, pk)
                            if existing_key is not None:
                                mappings.setdefault(table_name, {})[source_key] = existing_key
                                continue
                            # Preserve a source PK only if that key isn't occupied; otherwise
                            # generate a fresh ID and keep dependent foreign keys coherent.
                            try:
                                new_key = insert_row(table_name, values, pk, source_key)
                            except sqlite3.IntegrityError:
                                existing_key = lookup_existing(table_name, values, pk)
                                if existing_key is None:
                                    continue
                                new_key = existing_key
                            if new_key is not None:
                                mappings.setdefault(table_name, {})[source_key] = new_key
                        except (sqlite3.Error, KeyError, ValueError, TypeError):
                            continue
                target.commit()
                target.execute("PRAGMA foreign_keys=ON")
                return True
            except Exception:
                target.rollback()
                try: target.execute("PRAGMA foreign_keys=ON")
                except sqlite3.Error: pass
                raise
    except (sqlite3.Error, OSError, ValueError) as exc:
        print(f"[InnerCly] Account recovery from {source_path.parent.name} failed safely: {exc}")
        return False


def _recover_account_from_previous_version(username: str, password: str) -> bool:
    """If a valid account is in an older extracted release, merge it into this DB."""
    current_path = _current_sqlite_path()
    if current_path is None or not current_path.exists():
        return False
    for candidate in _previous_innercly_databases(current_path):
        try:
            uri = _readonly_sqlite_uri(candidate)
            with sqlite3.connect(uri, uri=True, timeout=8) as source:
                source.row_factory = sqlite3.Row
                found_tables = _sqlite_table_names(source)
                if "users" not in found_tables:
                    continue
                columns = {r[1] for r in source.execute("PRAGMA table_info(users)").fetchall()}
                if not {"id", "username", "password_hash"}.issubset(columns):
                    continue
                row = source.execute('SELECT * FROM "users" WHERE lower("username")=? LIMIT 1', (username.lower(),)).fetchone()
                if not row or not verify_password(password, row["password_hash"]):
                    continue
                verified_hash = str(row["password_hash"])
            if _copy_previous_database_data(candidate, current_path, username, verified_hash):
                print(f"[InnerCly] Recovered authenticated account from {candidate.parent.name}; source DB left untouched.")
                return True
        except (sqlite3.Error, OSError, KeyError, ValueError) as exc:
            print(f"[InnerCly] Skipped previous account database {candidate.parent.name}: {exc}")
            continue
    return False


def user_has_premium(user: Optional[User], now: Optional[datetime] = None) -> bool:
    if user is None:
        return False
    if (getattr(user, "role", "member") or "member").lower() == "owner":
        return True
    if any(b.active and b.badge_type in {"blue", "purple", "gold", "green"} for b in getattr(user, "account_badges", [])):
        return True
    subscription = getattr(user, "premium_subscription", None)
    if not subscription or subscription.status != "active":
        return False
    now = now or datetime.now(timezone.utc)
    expires = subscription.expires_at
    if expires is None:
        return True
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    return expires > now


def active_account_badges(user: Optional[User]) -> list[dict]:
    """Return a consistent, public-safe view of a user's currently active badges."""
    if user is None:
        return []
    active = [
        {"type": badge.badge_type, "active": bool(badge.active), "reason": badge.reason}
        for badge in getattr(user, "account_badges", [])
        if badge.active
    ]
    # Silver is a derived membership badge; it is never manually grantable.
    if user_has_premium(user) and not any(item["type"] == "silver" for item in active):
        active.append({"type": "silver", "active": True, "reason": "Premium access"})
    return active


def user_payload(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "avatar_data": user.avatar_data,
        "bio": getattr(user, "bio", "") or "",
        "role": getattr(user, "role", "member") or "member",
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "badges": active_account_badges(user),
    }


def token_fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def ip_fingerprint(request: Request, username: str) -> str:
    # Store a one-way fingerprint for a client+username pair rather than a raw IP.
    # Including username avoids one shared proxy address throttling every user together.
    ip = request.client.host if request.client else "unknown"
    raw = ip + "|" + username.lower() + "|innercly-login-throttle"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def cookie_secure_for_request(request: Request) -> bool:
    """Keep local loopback HTTP sessions usable, while requiring Secure on production URLs.

    Browser cookies are origin-bound; a Secure cookie issued from http://127.0.0.1
    is silently rejected by browsers. APP_ENV alone is not sufficient when someone
    starts the local app outside START_INNERCLY.bat.
    """
    hostname = (request.url.hostname or "").strip().lower().strip("[]")
    is_loopback = hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith(".localhost")
    if is_loopback:
        return request.url.scheme.lower() == "https"
    return APP_ENV != "development" or request.url.scheme.lower() == "https"


def set_auth_cookie(response: Response, token: str, request: Request) -> None:
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=int(SESSION_LIFETIME.total_seconds()),
        expires=datetime.now(timezone.utc) + SESSION_LIFETIME,
        httponly=True,
        secure=cookie_secure_for_request(request),
        samesite="lax",
        path="/",
    )


def create_session(user: User, response: Response, db: Session, request: Request) -> None:
    raw_token = secrets.token_urlsafe(40)
    now = datetime.now(timezone.utc)
    db.execute(delete(AuthSession).where(AuthSession.expires_at <= now))
    row = AuthSession(
        user_id=user.id,
        token_hash=token_fingerprint(raw_token),
        created_at=now,
        expires_at=now + SESSION_LIFETIME,
    )
    db.add(row)
    db.commit()
    set_auth_cookie(response, raw_token, request)


def current_user(request: Request, db: Session) -> Optional[User]:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    now = datetime.now(timezone.utc)
    row = db.scalar(
        select(AuthSession).where(
            AuthSession.token_hash == token_fingerprint(token),
            AuthSession.expires_at > now,
        )
    )
    return row.user if row else None


def require_same_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if not origin:
        return  # Non-browser clients may omit Origin; cookie SameSite remains enabled.
    parsed = urlparse(origin)
    if parsed.netloc.lower() != request.url.netloc.lower():
        raise HTTPException(status_code=403, detail="Cross-origin requests are not allowed.")


app = FastAPI(title="InnerCly", docs_url=None, redoc_url=None, openapi_url=None)

# Serve the app's real static assets. Without this mount, index.html loads but
# /assets/* logo and other packaged image requests return 404.
ASSETS_DIR = BASE_DIR / "assets"
if ASSETS_DIR.is_dir():
    app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()")
    response.headers.setdefault("Cache-Control", "no-store" if request.url.path.startswith("/api/auth") else "no-cache")
    return response


@app.on_event("startup")
def create_schema() -> None:
    Base.metadata.create_all(bind=engine)
    # create_all doesn't ALTER an existing table. Add only the missing columns, preserving
    # existing accounts and data in both local SQLite and PostgreSQL databases.
    market_columns = {c["name"] for c in inspect(engine).get_columns("rt_market_listings")}
    user_columns = {c["name"] for c in inspect(engine).get_columns("users")}
    comment_columns = {c["name"] for c in inspect(engine).get_columns("rt_post_comments")}
    post_columns = {c["name"] for c in inspect(engine).get_columns("rt_posts")}
    listing_columns = {c["name"] for c in inspect(engine).get_columns("rt_market_listings")}
    saved_columns = {c["name"] for c in inspect(engine).get_columns("rt_saved_items")}
    dm_columns = {c["name"] for c in inspect(engine).get_columns("rt_direct_messages")}
    group_message_columns = {c["name"] for c in inspect(engine).get_columns("rt_group_messages")}
    checkout_columns = {c["name"] for c in inspect(engine).get_columns("rt_checkout_payments")} if inspect(engine).has_table("rt_checkout_payments") else set()
    with engine.begin() as conn:
        if "price_amount" not in market_columns:
            conn.execute(text("ALTER TABLE rt_market_listings ADD COLUMN price_amount NUMERIC(20, 6)"))
        if "currency_code" not in market_columns:
            conn.execute(text("ALTER TABLE rt_market_listings ADD COLUMN currency_code VARCHAR(3)"))
        if "role" not in user_columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'member'"))
        if "bio" not in user_columns:
            conn.execute(text("ALTER TABLE users ADD COLUMN bio VARCHAR(280) NOT NULL DEFAULT ''"))
        if "parent_comment_id" not in comment_columns:
            conn.execute(text("ALTER TABLE rt_post_comments ADD COLUMN parent_comment_id INTEGER REFERENCES rt_post_comments(id) ON DELETE CASCADE"))
        if "visibility" not in post_columns:
            conn.execute(text("ALTER TABLE rt_posts ADD COLUMN visibility VARCHAR(12) NOT NULL DEFAULT 'public'"))
        if "category" not in listing_columns:
            conn.execute(text("ALTER TABLE rt_market_listings ADD COLUMN category VARCHAR(32) NOT NULL DEFAULT 'General'"))
        if "listing_type" not in listing_columns:
            conn.execute(text("ALTER TABLE rt_market_listings ADD COLUMN listing_type VARCHAR(16) NOT NULL DEFAULT 'physical'"))
        if "collection_name" not in saved_columns:
            conn.execute(text("ALTER TABLE rt_saved_items ADD COLUMN collection_name VARCHAR(64) NOT NULL DEFAULT 'Saved'"))
        if "reply_to_id" not in dm_columns:
            conn.execute(text("ALTER TABLE rt_direct_messages ADD COLUMN reply_to_id INTEGER"))
        if "edited_at" not in dm_columns:
            conn.execute(text("ALTER TABLE rt_direct_messages ADD COLUMN edited_at TIMESTAMP"))
        if "reply_to_id" not in group_message_columns:
            conn.execute(text("ALTER TABLE rt_group_messages ADD COLUMN reply_to_id INTEGER"))
        if "edited_at" not in group_message_columns:
            conn.execute(text("ALTER TABLE rt_group_messages ADD COLUMN edited_at TIMESTAMP"))
        live_columns = {c["name"] for c in inspect(engine).get_columns("rt_live_streams")}
        if "show_in_feed" not in live_columns:
            conn.execute(text("ALTER TABLE rt_live_streams ADD COLUMN show_in_feed BOOLEAN NOT NULL DEFAULT FALSE"))
        # The monetization checkout table may exist from an earlier test build. Add
        # only the fields introduced by the Marketplace checkout flow; never replace
        # an existing table or discard pending-payment history.
        if checkout_columns:
            if "listing_id" not in checkout_columns:
                conn.execute(text("ALTER TABLE rt_checkout_payments ADD COLUMN listing_id INTEGER REFERENCES rt_market_listings(id) ON DELETE SET NULL"))
            if "seller_user_id" not in checkout_columns:
                conn.execute(text("ALTER TABLE rt_checkout_payments ADD COLUMN seller_user_id INTEGER REFERENCES users(id) ON DELETE SET NULL"))
            if "currency_code" not in checkout_columns:
                conn.execute(text("ALTER TABLE rt_checkout_payments ADD COLUMN currency_code VARCHAR(3) NOT NULL DEFAULT 'USD'"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_rt_checkout_payments_listing_id ON rt_checkout_payments (listing_id)"))
            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_rt_checkout_payments_seller_user_id ON rt_checkout_payments (seller_user_id)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_rt_post_comments_parent_comment_id ON rt_post_comments (parent_comment_id)"))
    # The configured Owner username is authoritative. Older releases may have left
    # a different account marked Owner, which would hide the Owner-only panel from
    # the configured owner account. Normalize to one Owner without changing account data; other legacy
    # Owner roles become Administrators and can still help run the community.
    with SessionLocal() as db:
        configured_owner = db.scalar(select(User).where(func.lower(User.username) == OWNER_USERNAME).limit(1))
        if configured_owner:
            changed = False
            for legacy_owner in db.scalars(select(User).where(User.role == "owner", User.id != configured_owner.id)).all():
                legacy_owner.role = "administrator"
                changed = True
                print(f"[InnerCly] Legacy Owner @{legacy_owner.username} changed to Administrator; configured Owner is @{OWNER_USERNAME}.")
            if (configured_owner.role or "member").lower() != "owner":
                configured_owner.role = "owner"
                changed = True
                print(f"[InnerCly] Owner role enabled for @{configured_owner.username}.")
            # The configured official InnerCly account automatically receives its gold badge.
            # Badge history is recorded only when the badge is first created.
            gold_badge = db.scalar(select(RtAccountBadge).where(
                RtAccountBadge.user_id == configured_owner.id,
                RtAccountBadge.badge_type == "gold"
            ))
            if gold_badge is None:
                gold_badge = RtAccountBadge(
                    user_id=configured_owner.id, badge_type="gold", active=True,
                    reason="Official InnerCly account designated by the configured Owner username.",
                    granted_by=configured_owner.id
                )
                db.add(gold_badge)
                db.flush()
                db.add(RtBadgeAudit(
                    actor_id=configured_owner.id, target_user_id=configured_owner.id,
                    badge_type="gold", active=True,
                    reason="Official InnerCly account designated by the configured Owner username."
                ))
                changed = True
            elif not gold_badge.active:
                gold_badge.active = True
                gold_badge.reason = "Official InnerCly account designated by the configured Owner username."
                gold_badge.granted_by = configured_owner.id
                gold_badge.updated_at = datetime.now(timezone.utc)
                db.add(RtBadgeAudit(actor_id=configured_owner.id, target_user_id=configured_owner.id,
                                    badge_type="gold", active=True, reason=gold_badge.reason))
                changed = True
            if changed:
                db.commit()


@app.get("/health")
def health(db: Session = Depends(get_db)) -> dict:
    db.execute(select(1))
    return {"ok": True, "service": "InnerCly", "build": "v133"}


@app.get("/api/build")
def build_info(request: Request) -> dict:
    # Report the cookie behavior for this exact browser origin, not only APP_ENV.
    hostname = (request.url.hostname or "").strip().lower().strip("[]")
    is_loopback_http = (hostname in {"localhost", "127.0.0.1", "::1"} or hostname.endswith(".localhost")) and request.url.scheme.lower() != "https"
    is_local = APP_ENV == "development" or is_loopback_http
    return {"service": "InnerCly", "build": "v133", "mode": "local-testing" if is_local else "production", "cookie_secure": cookie_secure_for_request(request)}


@app.get("/")
def home():
    # Prevent a stale login page from being served from browser caches.
    return FileResponse(
        BASE_DIR / "index.html",
        media_type="text/html; charset=utf-8",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache", "Expires": "0"},
    )


@app.get("/welcome")
def welcome_website():
    """Serve InnerCly's public-facing landing website without replacing the social app at /."""
    return FileResponse(
        BASE_DIR / "website" / "index.html",
        media_type="text/html; charset=utf-8",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache"},
    )


@app.get("/site-config.js")
def website_config():
    """Serve the landing site's app URL configuration for the integrated deployment."""
    return FileResponse(
        BASE_DIR / "website" / "site-config.js",
        media_type="application/javascript; charset=utf-8",
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/api/auth/me")
def auth_me(request: Request, db: Session = Depends(get_db)) -> dict:
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="No active InnerCly session.")
    return {"user": user_payload(user)}


@app.post("/api/auth/register", status_code=status.HTTP_201_CREATED)
def register(body: RegisterBody, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    existing = db.scalar(select(User).where(func.lower(User.username) == body.username.lower()))
    if existing:
        raise HTTPException(status_code=409, detail="That username is already registered. Try signing in.")
    # Only the server-configured username can become Owner. If an older database
    # still has a different Owner, that account is downgraded to Administrator at
    # this explicit configured-owner registration path (and on next startup).
    bootstrap_owner = body.username.lower() == OWNER_USERNAME
    user = User(
        username=body.username,
        display_name=body.display_name,
        password_hash=hash_password(body.password),
        avatar_data=body.avatar_data,
        role="owner" if bootstrap_owner else "member",
    )
    db.add(user)
    try:
        db.flush()
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="That username is already registered. Try signing in.")
    if bootstrap_owner:
        for legacy_owner in db.scalars(select(User).where(User.role == "owner", User.id != user.id)).all():
            legacy_owner.role = "administrator"
        db.commit()
        db.refresh(user)
    create_session(user, response, db, request)
    return {"user": user_payload(user)}


@app.post("/api/auth/login")
def login(body: LoginBody, request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    fingerprint = ip_fingerprint(request, body.username)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=15)
    recent = db.scalar(
        select(func.count(FailedLogin.id)).where(
            FailedLogin.ip_fingerprint == fingerprint,
            FailedLogin.attempted_at >= cutoff,
        )
    ) or 0
    if recent >= 10:
        raise HTTPException(status_code=429, detail="Too many failed sign-in attempts. Wait 15 minutes and try again.")
    user = db.scalar(select(User).where(func.lower(User.username) == body.username.lower()))
    if not user or not verify_password(body.password, user.password_hash):
        # Older release folders may contain the correct account database while this
        # folder has a different/partial copy. Try only databases where the submitted
        # password validates against the stored hash; source files are read-only.
        db.rollback()
        recovered = _recover_account_from_previous_version(body.username, body.password)
        if recovered:
            db.expire_all()
            user = db.scalar(select(User).where(func.lower(User.username) == body.username.lower()))
        if not user or not verify_password(body.password, user.password_hash):
            db.add(FailedLogin(ip_fingerprint=fingerprint, attempted_at=datetime.now(timezone.utc)))
            db.commit()
            # Return the same error whether the username exists or not.
            raise HTTPException(status_code=401, detail="Username or password is incorrect.")
    db.execute(delete(FailedLogin).where(FailedLogin.ip_fingerprint == fingerprint))
    db.commit()
    create_session(user, response, db, request)
    return {"user": user_payload(user)}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        db.execute(delete(AuthSession).where(AuthSession.token_hash == token_fingerprint(token)))
        db.commit()
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, secure=cookie_secure_for_request(request), samesite="lax")
    return {"ok": True}


# ---- Authenticated real-time social API (Stories intentionally excluded) ----
def require_rt_user(request: Request, db: Session) -> User:
    user = current_user(request, db)
    if not user:
        raise HTTPException(status_code=401, detail="Sign in to your InnerCly account first.")
    return user


def require_owner(request: Request, db: Session) -> User:
    user = require_rt_user(request, db)
    if (getattr(user, "role", "member") or "member") != "owner":
        raise HTTPException(status_code=403, detail="Only the InnerCly Owner can manage account roles.")
    return user


def require_moderator(request: Request, db: Session) -> User:
    user = require_rt_user(request, db)
    if (getattr(user, "role", "member") or "member").lower() not in {"moderator", "administrator", "owner"}:
        raise HTTPException(status_code=403, detail="This action is limited to authorized community moderators.")
    return user


def _rt_is_blocked(db: Session, a: int, b: int) -> bool:
    if a == b:
        return False
    return db.scalar(select(RtUserBlock.id).where(or_(
        and_(RtUserBlock.blocker_id == a, RtUserBlock.blocked_id == b),
        and_(RtUserBlock.blocker_id == b, RtUserBlock.blocked_id == a),
    ))) is not None


def _rt_message_reactions(db: Session, message_type: str, message_id: int, user_id: int) -> list[dict]:
    rows = db.scalars(select(RtMessageReaction).where(
        RtMessageReaction.message_type == message_type,
        RtMessageReaction.message_id == message_id,
    )).all()
    grouped: dict[str, dict] = {}
    for row in rows:
        entry = grouped.setdefault(row.emoji, {"emoji": row.emoji, "count": 0, "mine": False})
        entry["count"] += 1
        if row.user_id == user_id:
            entry["mine"] = True
    return sorted(grouped.values(), key=lambda value: (-value["count"], value["emoji"]))


def _rt_user(user: User) -> dict:
    return {"id": user.id, "username": user.username, "display_name": user.display_name, "avatar_data": user.avatar_data, "bio": getattr(user, "bio", "") or "", "role": getattr(user, "role", "member") or "member", "badges": active_account_badges(user)}

def _rt_iso(value: Optional[datetime]) -> Optional[str]:
    if value is None:
        return None
    # SQLite strips timezone metadata from DateTime columns; normalize those values as UTC
    # so browsers on other time zones sort and expire shared Stories consistently.
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()

def _rt_check_media(value: Optional[str], *, images_only: bool = False, max_chars: int = 3_000_000) -> Optional[str]:
    if not value:
        return None
    if len(value) > max_chars:
        raise HTTPException(status_code=413, detail="That upload is too large. Choose a smaller file.")
    allowed = ("data:image/jpeg;base64,", "data:image/png;base64,", "data:image/webp;base64,", "data:image/gif;base64,")
    if not images_only:
        allowed = allowed + ("data:video/webm;base64,", "data:video/mp4;base64,", "data:video/quicktime;base64,", "data:audio/webm;base64,", "data:audio/ogg;base64,", "data:audio/mp4;base64,", "data:audio/mpeg;base64,")
    if not value.startswith(allowed):
        raise HTTPException(status_code=415, detail="Use a supported image or video file.")
    return value

def _rt_pair(a: int, b: int) -> tuple[int, int]:
    return (a, b) if a < b else (b, a)

def _rt_are_friends(db: Session, a: int, b: int) -> bool:
    lo, hi = _rt_pair(a, b)
    return db.scalar(select(RtFriendship.id).where(RtFriendship.user_a_id == lo, RtFriendship.user_b_id == hi)) is not None

def _rt_can_view_post(db: Session, viewer_id: int, post: RtPost) -> bool:
    if post.author_id == viewer_id:
        return True
    if _rt_is_blocked(db, viewer_id, post.author_id):
        return False
    audience = (getattr(post, "visibility", "public") or "public").lower()
    if audience == "friends":
        return _rt_are_friends(db, viewer_id, post.author_id)
    return audience == "public"

def _rt_notify(db: Session, user_id: int, text: str, link_type: str = "", link_id: Optional[int] = None) -> None:
    db.add(RtNotification(user_id=user_id, text=text[:500], link_type=link_type, link_id=link_id))

def _rt_post_json(db: Session, post: RtPost, viewer_id: int) -> dict:
    author = db.get(User, post.author_id)
    top_level_rows = db.scalars(
        select(RtPostComment).where(
            RtPostComment.post_id == post.id, RtPostComment.parent_comment_id.is_(None)
        ).order_by(RtPostComment.created_at.asc(), RtPostComment.id.asc()).limit(100)
    ).all()
    top_level_ids = [comment.id for comment in top_level_rows]
    reply_rows = db.scalars(
        select(RtPostComment).where(
            RtPostComment.post_id == post.id, RtPostComment.parent_comment_id.in_(top_level_ids)
        ).order_by(RtPostComment.created_at.asc(), RtPostComment.id.asc()).limit(300)
    ).all() if top_level_ids else []
    comment_rows = sorted([*top_level_rows, *reply_rows], key=lambda row: (row.created_at, row.id))
    total_comment_count = db.scalar(select(func.count(RtPostComment.id)).where(RtPostComment.post_id == post.id)) or 0
    comments_by_id: dict[int, dict] = {}
    comments: list[dict] = []
    for comment in comment_rows:
        comment_author = db.get(User, comment.author_id)
        comments_by_id[comment.id] = {
            "id": comment.id,
            "parent_comment_id": comment.parent_comment_id,
            "text": comment.text,
            "created_at": _rt_iso(comment.created_at),
            "author": _rt_user(comment_author) if comment_author else {"display_name": "Unknown", "username": "unknown", "avatar_data": None},
            "replies": [],
        }
    for comment in comment_rows:
        item = comments_by_id[comment.id]
        if comment.parent_comment_id:
            parent = comments_by_id.get(comment.parent_comment_id)
            if parent:
                parent["replies"].append(item)
        else:
            comments.append(item)
    liked = db.scalar(select(RtPostLike.id).where(RtPostLike.post_id == post.id, RtPostLike.user_id == viewer_id)) is not None
    like_count = db.scalar(select(func.count(RtPostLike.id)).where(RtPostLike.post_id == post.id)) or 0
    can_follow_author = bool(author and author.id != viewer_id)
    is_following_author = bool(can_follow_author and db.scalar(select(RtUserFollow.id).where(
        RtUserFollow.follower_id == viewer_id, RtUserFollow.following_id == post.author_id
    )) is not None)
    # The list endpoint uses load_only() so large video data is never fetched just to
    # refresh the feed. Trust the persisted media_type for current uploads; only fall
    # back to reading media_data for older posts whose media_type was not normalized.
    is_video = str(post.media_type or "").lower() == "video"
    media_data = None if is_video else post.media_data
    if not is_video:
        is_video = bool(media_data and str(media_data).startswith("data:video/"))
    media_value = f"/api/posts/{post.id}/media" if is_video else media_data
    resolved_media_type = "video" if is_video else post.media_type
    return {
        "id": post.id, "text": post.text, "media_data": media_value, "media_type": resolved_media_type,
        "created_at": _rt_iso(post.created_at), "author": _rt_user(author) if author else {"display_name": "Unknown", "username": "unknown", "avatar_data": None},
        "like_count": like_count, "liked_by_me": liked,
        "comments": comments, "comment_count": total_comment_count,
        "can_follow_author": can_follow_author, "is_following_author": is_following_author,
        "can_delete": post.author_id == viewer_id,
        "view_count": db.scalar(select(func.count(RtPostView.id)).where(RtPostView.post_id == post.id)) or 0,
    }

def _rt_group_json(db: Session, group: RtGroup, user: User) -> dict:
    owner = db.get(User, group.owner_id)
    members = db.scalar(select(func.count(RtGroupMember.id)).where(RtGroupMember.group_id == group.id)) or 0
    joined = db.scalar(select(RtGroupMember.id).where(RtGroupMember.group_id == group.id, RtGroupMember.user_id == user.id)) is not None
    return {"id": group.id, "name": group.name, "description": group.description, "visibility": group.visibility,
            "created_at": _rt_iso(group.created_at), "owner": _rt_user(owner) if owner else None, "member_count": members,
            "joined": joined, "is_owner": group.owner_id == user.id}

def _rt_listing_json(db: Session, listing: RtListing, user: User) -> dict:
    seller = db.get(User, listing.seller_id)
    return {"id": listing.id, "title": listing.title, "category": getattr(listing, "category", "General") or "General", "listing_type": getattr(listing, "listing_type", "physical") or "physical", "price": listing.price,
            "price_amount": format(listing.price_amount.normalize(), "f") if listing.price_amount is not None else None,
            "currency_code": listing.currency_code,
            "description": listing.description, "image_data": listing.image_data,
            "status": listing.status, "created_at": _rt_iso(listing.created_at),
            "seller": _rt_user(seller) if seller else None, "is_seller": listing.seller_id == user.id}

def _rt_delivery_json(db: Session, row: RtDelivery, user: User) -> dict:
    listing = db.get(RtListing, row.listing_id); buyer = db.get(User, row.buyer_id); seller = db.get(User, row.seller_id)
    return {"id": row.id, "listing_id": row.listing_id, "listing_title": listing.title if listing else "Unavailable listing",
            "phone": row.phone if row.buyer_id == user.id or row.seller_id == user.id else None,
            "address": row.address if row.buyer_id == user.id or row.seller_id == user.id else None, "note": row.note,
            "status": row.status, "created_at": _rt_iso(row.created_at), "updated_at": _rt_iso(row.updated_at),
            "buyer": _rt_user(buyer) if buyer else None, "seller": _rt_user(seller) if seller else None,
            "is_seller": row.seller_id == user.id, "is_buyer": row.buyer_id == user.id}

@app.patch("/api/auth/profile")
def update_profile(body: ProfileUpdateBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    if body.username is not None:
        candidate = body.username.strip().lower()
        existing = db.scalar(select(User.id).where(func.lower(User.username) == candidate, User.id != user.id))
        if existing is not None:
            raise HTTPException(status_code=409, detail="That username is already in use. Choose another one.")
        user.username = candidate
    user.display_name = body.display_name
    user.bio = body.bio
    if body.avatar_data is not None:
        user.avatar_data = _rt_check_media(body.avatar_data, images_only=True, max_chars=MAX_AVATAR_CHARS)
    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail="That username is already in use. Choose another one.") from exc
    db.refresh(user)
    return {"user": user_payload(user)}

def _rt_normalize_story_data_url(value: Optional[str], media_type: str) -> Optional[str]:
    if not value:
        return None
    # Repair the older malformed recorder format where codec parameters appeared before
    # the first comma. The resulting URL is a standard data URL before it is stored.
    low = value.lower()
    base64_at = low.find(";base64,")
    first_comma = value.find(",")
    if base64_at >= 0 and 0 <= first_comma < base64_at:
        header = value[5:base64_at]
        mime = (header.split(";")[0] or ("video/webm" if media_type == "video" else "image/jpeg")).strip().lower()
        if mime.startswith(("video/", "image/")):
            value = f"data:{mime};base64," + value[base64_at + len(";base64,"):]
    if len(value) > 11_800_000:
        raise HTTPException(status_code=413, detail="That Story media is too large. Choose an image under 8 MB or a shorter video.")
    if ";base64," not in value[:100].lower():
        raise HTTPException(status_code=415, detail="Story media must be a supported base64 image or video.")
    head, payload = value.split(",", 1)
    mime = head[5:].split(";", 1)[0].lower()
    image_mimes = ("image/jpeg", "image/png", "image/webp", "image/gif")
    video_mimes = ("video/webm", "video/mp4", "video/quicktime")
    allowed = video_mimes if media_type == "video" else image_mimes if media_type == "photo" else image_mimes + video_mimes
    if mime not in allowed:
        raise HTTPException(status_code=415, detail="Choose a supported JPEG, PNG, WebP, GIF, WebM, MP4, or QuickTime Story file.")
    try:
        # Validate the payload and guard against declared base64 strings that cannot be decoded.
        decoded = base64.b64decode(payload, validate=True)
    except Exception:
        raise HTTPException(status_code=422, detail="The Story media file is damaged. Please choose or record it again.")
    if not decoded:
        raise HTTPException(status_code=422, detail="The Story media file is empty.")
    return value


def _rt_story_visible_ids(db: Session, user_id: int) -> set[int]:
    pairs = db.scalars(select(RtFriendship).where(or_(RtFriendship.user_a_id == user_id, RtFriendship.user_b_id == user_id))).all()
    visible = {user_id}
    for pair in pairs:
        visible.add(pair.user_b_id if pair.user_a_id == user_id else pair.user_a_id)
    return visible


def _rt_story_json(db: Session, story: RtStory, viewer_id: int) -> dict:
    author = db.get(User, story.author_id)
    return {
        "id": story.id,
        "text": story.text,
        "media_type": story.media_type,
        "media_url": f"/api/stories/{story.id}/media" if story.media_data else None,
        "has_media": bool(story.media_data),
        "created_at": _rt_iso(story.created_at),
        "expires_at": _rt_iso(story.expires_at),
        "author": ({"id": author.id, "username": author.username, "display_name": author.display_name, "badges": active_account_badges(author)} if author else {"id": 0, "username": "unknown", "display_name": "Unknown", "badges": []}),
        "can_delete": story.author_id == viewer_id,
    }


def _rt_delete_expired_stories(db: Session) -> None:
    now = datetime.now(timezone.utc)
    result = db.execute(delete(RtStory).where(RtStory.expires_at <= now))
    if result.rowcount:
        db.commit()


@app.get("/api/stories")
def rt_list_stories(request: Request, db: Session = Depends(get_db)) -> dict:
    user = require_rt_user(request, db)
    _rt_delete_expired_stories(db)
    visible_ids = _rt_story_visible_ids(db, user.id)
    rows = db.scalars(
        select(RtStory)
        .where(RtStory.author_id.in_(visible_ids), RtStory.expires_at > datetime.now(timezone.utc))
        .order_by(RtStory.created_at.asc(), RtStory.id.asc())
        .limit(300)
    ).all()
    return {"items": [_rt_story_json(db, story, user.id) for story in rows], "expires_after_hours": 24}


@app.post("/api/stories", status_code=status.HTTP_201_CREATED)
def rt_create_story(body: RtStoryBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    _rt_delete_expired_stories(db)
    text = body.text.strip()
    media_type = body.media_type
    media = _rt_normalize_story_data_url(body.media_data, media_type) if body.media_data else None
    if media and media_type == "text":
        media_type = "video" if media.startswith("data:video/") else "photo"
    if not text and not media:
        raise HTTPException(status_code=422, detail="Write something or add a photo/video to your Story.")
    if media and not (media_type in ("photo", "video")):
        raise HTTPException(status_code=422, detail="Choose a photo or video for this Story.")
    active_count = db.scalar(select(func.count(RtStory.id)).where(RtStory.author_id == user.id, RtStory.expires_at > datetime.now(timezone.utc))) or 0
    if active_count >= 50:
        raise HTTPException(status_code=429, detail="You have 50 active Stories. Delete one or wait for older Stories to expire.")
    now = datetime.now(timezone.utc)
    row = RtStory(author_id=user.id, text=text, media_data=media, media_type=media_type if media else "text", created_at=now, expires_at=now + timedelta(hours=24))
    db.add(row); db.commit(); db.refresh(row)
    # Let friends know a new status is available without exposing content in notification text.
    visible_to = _rt_story_visible_ids(db, user.id) - {user.id}
    for friend_id in visible_to:
        _rt_notify(db, friend_id, f"{user.display_name} shared a new Story.", "story", row.id)
    db.commit()
    return {"item": _rt_story_json(db, row, user.id)}


@app.get("/api/stories/{story_id}/media")
def rt_story_media(story_id: int, request: Request, db: Session = Depends(get_db)) -> Response:
    user = require_rt_user(request, db)
    story = db.scalar(select(RtStory).where(RtStory.id == story_id, RtStory.expires_at > datetime.now(timezone.utc)))
    if not story or not story.media_data:
        raise HTTPException(status_code=404, detail="This Story media is unavailable or has expired.")
    if story.author_id not in _rt_story_visible_ids(db, user.id):
        raise HTTPException(status_code=404, detail="This Story media is unavailable.")
    try:
        header, encoded = story.media_data.split(",", 1)
        mime = header[5:].split(";", 1)[0].lower()
        data = base64.b64decode(encoded, validate=True)
    except Exception:
        raise HTTPException(status_code=500, detail="This Story media could not be read.")
    # Support media seeking in browser video players, while serving only the authorized Story.
    range_header = request.headers.get("range", "")
    common = {"Accept-Ranges": "bytes", "Cache-Control": "private, max-age=60", "X-Content-Type-Options": "nosniff"}
    if range_header.startswith("bytes=") and "," not in range_header:
        try:
            left, right = range_header[6:].split("-", 1)
            if left:
                start = int(left); end = int(right) if right else len(data) - 1
            else:
                suffix = int(right); start = max(0, len(data) - suffix); end = len(data) - 1
            if start < 0 or start >= len(data) or end < start:
                return Response(status_code=416, headers={**common, "Content-Range": f"bytes */{len(data)}"})
            end = min(end, len(data) - 1)
            chunk = data[start:end + 1]
            return Response(chunk, status_code=206, media_type=mime, headers={**common, "Content-Range": f"bytes {start}-{end}/{len(data)}", "Content-Length": str(len(chunk))})
        except (ValueError, TypeError):
            pass
    return Response(data, media_type=mime, headers={**common, "Content-Length": str(len(data))})


@app.delete("/api/stories/{story_id}")
def rt_delete_story(story_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    story = db.get(RtStory, story_id)
    if not story or story.author_id != user.id:
        raise HTTPException(status_code=404, detail="Story not found.")
    db.delete(story); db.commit()
    return {"ok": True}


@app.get("/api/posts")
def rt_list_posts(request: Request, db: Session = Depends(get_db), limit: int = 60) -> dict:
    user = require_rt_user(request, db)
    limit = max(1, min(limit, 100))
    blocked_ids = set(db.scalars(select(RtUserBlock.blocked_id).where(RtUserBlock.blocker_id == user.id)).all())
    blocked_ids.update(db.scalars(select(RtUserBlock.blocker_id).where(RtUserBlock.blocked_id == user.id)).all())
    muted_ids = set(db.scalars(select(RtUserMute.muted_id).where(RtUserMute.muter_id == user.id)).all())
    query = select(RtPost).options(load_only(
        RtPost.id, RtPost.author_id, RtPost.text, RtPost.media_type, RtPost.visibility, RtPost.created_at
    ))
    hidden_ids = blocked_ids | muted_ids
    if hidden_ids:
        query = query.where(RtPost.author_id.not_in(hidden_ids))
    candidates = db.scalars(query.order_by(RtPost.created_at.desc(), RtPost.id.desc()).limit(min(200, limit * 4))).all()
    visible = [p for p in candidates if _rt_can_view_post(db, user.id, p)][:limit]
    return {"items": [_rt_post_json(db, p, user.id) for p in visible]}


@app.post("/api/posts/{post_id}/view")
def rt_record_post_view(post_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    post = db.get(RtPost, post_id)
    if not post or not _rt_can_view_post(db, user.id, post):
        raise HTTPException(status_code=404, detail="Post not found.")
    if post.author_id == user.id:
        return {"ok": True, "counted": False}
    today = datetime.now(timezone.utc).date().isoformat()
    existing = db.scalar(select(RtPostView.id).where(RtPostView.post_id == post_id, RtPostView.viewer_id == user.id, RtPostView.view_date == today))
    if existing is None:
        db.add(RtPostView(post_id=post_id, viewer_id=user.id, view_date=today))
        db.commit()
    count = db.scalar(select(func.count(RtPostView.id)).where(RtPostView.post_id == post_id)) or 0
    return {"ok": True, "counted": existing is None, "view_count": count}

@app.post("/api/posts", status_code=status.HTTP_201_CREATED)
def rt_create_post(body: RtPostBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request); user = require_rt_user(request, db)
    text = body.text.strip(); media = _rt_check_media(body.media_data, max_chars=72_000_000)
    if not text and not media: raise HTTPException(status_code=422, detail="Write something or add a photo/video.")
    media_type = body.media_type if media else ""
    if media and media_type not in ("photo", "image", "gif", "video", "audio"):
        media_type = "video" if media.startswith("data:video/") else ("audio" if media.startswith("data:audio/") else ("gif" if media.startswith("data:image/gif") else "photo"))
    post = RtPost(author_id=user.id, text=text, media_data=media, media_type=media_type, visibility=body.visibility)
    db.add(post); db.commit(); db.refresh(post)
    # Shared posts do not duplicate or read Stories, which remain browser-local.
    return {"item": _rt_post_json(db, post, user.id)}

# Keep only a small bounded cache of decoded post videos. Feed refreshes never need
# video bytes, and range/seek requests can reuse this cache instead of decoding base64
# on each chunk. This cache is process-local and does not affect persistent post data.
_POST_VIDEO_CACHE: OrderedDict[int, tuple[str, bytes]] = OrderedDict()
_POST_VIDEO_CACHE_BYTES = 0
_POST_VIDEO_CACHE_LIMIT = 64 * 1024 * 1024
_POST_VIDEO_CACHE_LOCK = threading.Lock()

def _post_video_bytes(db: Session, post_id: int) -> tuple[str, bytes]:
    global _POST_VIDEO_CACHE_BYTES
    with _POST_VIDEO_CACHE_LOCK:
        cached = _POST_VIDEO_CACHE.get(post_id)
        if cached is not None:
            _POST_VIDEO_CACHE.move_to_end(post_id)
            return cached
    stored = db.scalar(select(RtPost.media_data).where(RtPost.id == post_id))
    if not stored or not str(stored).startswith("data:video/"):
        raise HTTPException(status_code=404, detail="Video not found.")
    try:
        header, encoded = str(stored).split(",", 1)
        mime = header[5:].split(";", 1)[0].strip().lower()
        if mime not in {"video/mp4", "video/webm", "video/quicktime"}:
            raise ValueError("Unsupported video type")
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError, base64.binascii.Error):
        raise HTTPException(status_code=415, detail="The stored video could not be read.")
    if len(raw) <= _POST_VIDEO_CACHE_LIMIT:
        with _POST_VIDEO_CACHE_LOCK:
            existing = _POST_VIDEO_CACHE.get(post_id)
            if existing is not None:
                _POST_VIDEO_CACHE.move_to_end(post_id)
                return existing
            _POST_VIDEO_CACHE[post_id] = (mime, raw)
            _POST_VIDEO_CACHE_BYTES += len(raw)
            while _POST_VIDEO_CACHE and _POST_VIDEO_CACHE_BYTES > _POST_VIDEO_CACHE_LIMIT:
                _old_id, (_old_mime, _old_raw) = _POST_VIDEO_CACHE.popitem(last=False)
                _POST_VIDEO_CACHE_BYTES -= len(_old_raw)
    return mime, raw

def _forget_post_video_cache(post_id: int) -> None:
    global _POST_VIDEO_CACHE_BYTES
    with _POST_VIDEO_CACHE_LOCK:
        old = _POST_VIDEO_CACHE.pop(post_id, None)
        if old is not None:
            _POST_VIDEO_CACHE_BYTES -= len(old[1])

@app.get("/api/posts/{post_id}/media")
def rt_get_post_media(post_id: int, request: Request, db: Session = Depends(get_db)) -> Response:
    """Serve post video media with cached decode and HTTP Range support for seeking."""
    user = require_rt_user(request, db)
    post = db.get(RtPost, post_id)
    if not post or not _rt_can_view_post(db, user.id, post):
        raise HTTPException(status_code=404, detail="Video not found.")
    mime, raw = _post_video_bytes(db, post_id)
    total = len(raw)
    common = {
        "Accept-Ranges": "bytes",
        "Cache-Control": "private, max-age=300",
        "Content-Disposition": "inline",
        "X-Content-Type-Options": "nosniff",
    }
    range_header = request.headers.get("range")
    if range_header:
        match = re.fullmatch(r"bytes=(\d*)-(\d*)", range_header.strip())
        if not match or (not match.group(1) and not match.group(2)) or total == 0:
            return Response(status_code=416, headers={**common, "Content-Range": f"bytes */{total}"})
        if not match.group(1):
            suffix = int(match.group(2))
            if suffix <= 0:
                return Response(status_code=416, headers={**common, "Content-Range": f"bytes */{total}"})
            start, end = max(0, total - suffix), total - 1
        else:
            start = int(match.group(1))
            end = int(match.group(2)) if match.group(2) else total - 1
            end = min(end, total - 1)
        if start >= total or end < start:
            return Response(status_code=416, headers={**common, "Content-Range": f"bytes */{total}"})
        chunk = raw[start:end + 1]
        return Response(chunk, status_code=206, media_type=mime, headers={**common, "Content-Range": f"bytes {start}-{end}/{total}", "Content-Length": str(len(chunk))})
    return Response(raw, media_type=mime, headers={**common, "Content-Length": str(total)})


@app.delete("/api/posts/{post_id}")
def rt_delete_post(post_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request); user = require_rt_user(request, db)
    post = db.get(RtPost, post_id)
    if not post: raise HTTPException(status_code=404, detail="Post not found.")
    if post.author_id != user.id: raise HTTPException(status_code=403, detail="You can only delete your own posts.")
    db.delete(post); db.commit(); _forget_post_video_cache(post_id); return {"ok": True}

@app.post("/api/posts/{post_id}/like")
def rt_toggle_like(post_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request); user = require_rt_user(request, db)
    post = db.get(RtPost, post_id)
    if not post or not _rt_can_view_post(db, user.id, post): raise HTTPException(status_code=404, detail="Post not found.")
    like = db.scalar(select(RtPostLike).where(RtPostLike.post_id == post_id, RtPostLike.user_id == user.id))
    if like: db.delete(like); liked = False
    else:
        db.add(RtPostLike(post_id=post_id, user_id=user.id)); liked = True
        if post.author_id != user.id: _rt_notify(db, post.author_id, f"{user.display_name} liked your post", "post", post.id)
    db.commit()
    count = db.scalar(select(func.count(RtPostLike.id)).where(RtPostLike.post_id == post_id)) or 0
    return {"liked": liked, "like_count": count}

@app.post("/api/posts/{post_id}/comments", status_code=status.HTTP_201_CREATED)
def rt_create_comment(post_id: int, body: RtCommentBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request); user = require_rt_user(request, db)
    post = db.get(RtPost, post_id)
    if not post or not _rt_can_view_post(db, user.id, post): raise HTTPException(status_code=404, detail="Post not found.")
    text_value = body.text.strip()
    if not text_value: raise HTTPException(status_code=422, detail="Write a comment first.")
    parent = None
    if body.parent_comment_id is not None:
        parent = db.get(RtPostComment, body.parent_comment_id)
        if not parent or parent.post_id != post_id:
            raise HTTPException(status_code=404, detail="The comment you are replying to was not found on this post.")
        if parent.parent_comment_id is not None:
            raise HTTPException(status_code=422, detail="Replies can be added to a main comment, not to another reply.")
    row = RtPostComment(post_id=post_id, author_id=user.id, parent_comment_id=parent.id if parent else None, text=text_value)
    db.add(row)
    if parent:
        if parent.author_id != user.id:
            _rt_notify(db, parent.author_id, f"{user.display_name} replied to your comment", "post", post.id)
        if post.author_id != user.id and (not parent or parent.author_id != post.author_id):
            _rt_notify(db, post.author_id, f"{user.display_name} replied in a comment on your post", "post", post.id)
    elif post.author_id != user.id:
        _rt_notify(db, post.author_id, f"{user.display_name} commented on your post", "post", post.id)
    db.commit(); db.refresh(row)
    return {"item": {"id": row.id, "parent_comment_id": row.parent_comment_id, "text": row.text, "created_at": _rt_iso(row.created_at), "author": _rt_user(user), "replies": []}}

@app.get("/api/admin/roles")
def admin_role_catalog(request: Request, db: Session = Depends(get_db)) -> dict:
    owner = require_owner(request, db)
    return {
        "current_user": user_payload(owner),
        "owner_username": OWNER_USERNAME,
        "roles": [{"role": role, "label": role.title(), "description": ROLE_DESCRIPTIONS[role], "assignable": role in ASSIGNABLE_ROLES} for role in ("member", "creator", "moderator", "administrator", "owner")],
    }


@app.get("/api/admin/users")
def admin_list_users(request: Request, q: str = "", db: Session = Depends(get_db)) -> dict:
    require_owner(request, db)
    query = select(User)
    term = q.strip().lower()[:80]
    if term:
        pattern = f"%{term}%"
        query = query.where(or_(func.lower(User.username).like(pattern), func.lower(User.display_name).like(pattern)))
    users = db.scalars(query.order_by(func.lower(User.username)).limit(60)).all()
    return {"items": [{"id": u.id, "username": u.username, "display_name": u.display_name, "role": getattr(u, "role", "member") or "member", "created_at": _rt_iso(u.created_at), "badges": active_account_badges(u)} for u in users]}


@app.get("/api/admin/role-audit")
def admin_role_audit(request: Request, db: Session = Depends(get_db)) -> dict:
    require_owner(request, db)
    rows = db.scalars(select(RtRoleAudit).order_by(RtRoleAudit.created_at.desc(), RtRoleAudit.id.desc()).limit(30)).all()
    actor_ids = {r.actor_id for r in rows}
    target_ids = {r.target_user_id for r in rows}
    people = {u.id: u for u in db.scalars(select(User).where(User.id.in_(actor_ids | target_ids))).all()} if (actor_ids or target_ids) else {}
    return {"items": [{"id": r.id, "actor": people.get(r.actor_id).username if people.get(r.actor_id) else "deleted account", "actor_badges": active_account_badges(people.get(r.actor_id)), "target": people.get(r.target_user_id).username if people.get(r.target_user_id) else "deleted account", "target_badges": active_account_badges(people.get(r.target_user_id)), "old_role": r.old_role, "new_role": r.new_role, "created_at": _rt_iso(r.created_at)} for r in rows]}


@app.patch("/api/admin/users/{username}/role")
def admin_update_user_role(username: str, body: RoleUpdateBody, request: Request, db: Session = Depends(get_db)) -> dict:
    owner = require_owner(request, db)
    require_same_origin(request)
    target = db.scalar(select(User).where(func.lower(User.username) == username.strip().lstrip("@").lower()))
    if not target:
        raise HTTPException(status_code=404, detail="That InnerCly account could not be found.")
    current_role = (getattr(target, "role", "member") or "member").lower()
    if current_role == "owner":
        raise HTTPException(status_code=400, detail="The Owner account is protected and cannot be changed here.")
    if target.id == owner.id:
        raise HTTPException(status_code=400, detail="You cannot change the Owner role from this panel.")
    if current_role != body.role:
        target.role = body.role
        db.add(RtRoleAudit(actor_id=owner.id, target_user_id=target.id, old_role=current_role, new_role=body.role))
        _rt_notify(db, target.id, f"Your InnerCly role changed from {current_role.title()} to {body.role.title()} by the Owner.", "role", target.id)
        db.commit()
        db.refresh(target)
    return {"ok": True, "user": {"id": target.id, "username": target.username, "display_name": target.display_name, "role": target.role}, "message": f"@{target.username} is now {target.role.title()}."}


BADGE_TYPES = {"blue", "purple", "gold", "green", "silver"}
BADGE_MEANINGS = {
    "blue": "Popular or notable account",
    "purple": "Professional or expert account",
    "gold": "Official InnerCly account",
    "green": "Trusted business",
    "silver": "Automatically assigned Premium membership status; cannot be manually granted.",
}


def _require_verified_creator(user: User, db: Session) -> None:
    if user.role != "owner" and db.scalar(select(RtVerifiedCreatorInvite.id).where(RtVerifiedCreatorInvite.user_id == user.id)) is None:
        raise HTTPException(status_code=403, detail="Verified Creators is private and invite-only. Ask the InnerCly Owner for an invitation.")


@app.get("/api/verified-creators/posts")
def list_verified_creator_posts(request: Request, db: Session = Depends(get_db)) -> dict:
    user = require_rt_user(request, db)
    _require_verified_creator(user, db)
    rows = db.scalars(select(RtVerifiedCreatorPost).order_by(RtVerifiedCreatorPost.created_at.desc(), RtVerifiedCreatorPost.id.desc()).limit(100)).all()
    authors = {u.id: u for u in db.scalars(select(User).where(User.id.in_({r.author_id for r in rows}))).all()} if rows else {}
    return {"items": [{"id": r.id, "text": r.text, "media_data": r.media_data, "media_type": r.media_type, "created_at": _rt_iso(r.created_at), "author": _rt_user(authors[r.author_id]) if r.author_id in authors else {"username": "deleted-account", "display_name": "Deleted account"}, "can_delete": r.author_id == user.id} for r in rows]}


@app.post("/api/verified-creators/posts", status_code=status.HTTP_201_CREATED)
def create_verified_creator_post(body: RtPostBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    _require_verified_creator(user, db)
    media = _rt_check_media(body.media_data, max_chars=72_000_000)
    if not body.text.strip() and not media:
        raise HTTPException(status_code=400, detail="Add text or choose a photo/video.")
    media_type = body.media_type if media else ""
    if media and media_type not in {"photo", "video"}:
        media_type = "video" if media.startswith("data:video/") else "photo"
    row = RtVerifiedCreatorPost(author_id=user.id, text=body.text.strip(), media_data=media, media_type=media_type)
    db.add(row); db.commit(); db.refresh(row)
    return {"item": {"id": row.id, "text": row.text, "media_data": row.media_data, "media_type": row.media_type, "created_at": _rt_iso(row.created_at), "author": _rt_user(user), "can_delete": True}}


@app.delete("/api/verified-creators/posts/{post_id}")
def delete_verified_creator_post(post_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    _require_verified_creator(user, db)
    row = db.get(RtVerifiedCreatorPost, post_id)
    if not row or (row.author_id != user.id and user.role != "owner"):
        raise HTTPException(status_code=404, detail="Private group post not found.")
    db.delete(row); db.commit()
    return {"ok": True}


@app.get("/api/verified-creators/access")
def verified_creators_access(request: Request, db: Session = Depends(get_db)) -> dict:
    user = require_rt_user(request, db)
    invite = db.scalar(select(RtVerifiedCreatorInvite).where(RtVerifiedCreatorInvite.user_id == user.id))
    return {"allowed": bool(invite) or user.role == "owner", "is_owner": user.role == "owner", "invited_at": _rt_iso(invite.created_at) if invite else None}


@app.get("/api/admin/badges")
def admin_list_badges(request: Request, q: str = "", db: Session = Depends(get_db)) -> dict:
    require_owner(request, db)
    term = q.strip().lower()[:80]
    query = select(User)
    if term:
        pattern = f"%{term}%"
        query = query.where(or_(func.lower(User.username).like(pattern), func.lower(User.display_name).like(pattern)))
    users = db.scalars(query.order_by(func.lower(User.username)).limit(40)).all()
    return {"types": [{"type": k, "meaning": v} for k, v in BADGE_MEANINGS.items()], "items": [{"username": u.username, "display_name": u.display_name, "badges": [{"type": b.badge_type, "active": bool(b.active), "reason": b.reason} for b in u.account_badges]} for u in users]}


@app.patch("/api/admin/users/{username}/badges")
def admin_update_badge(username: str, body: dict, request: Request, db: Session = Depends(get_db)) -> dict:
    owner = require_owner(request, db)
    require_same_origin(request)
    badge_type = str(body.get("badge", "")).strip().lower()
    active = bool(body.get("active", True))
    reason = str(body.get("reason", "")).strip()[:500]
    if badge_type not in BADGE_TYPES:
        raise HTTPException(status_code=400, detail="Choose a valid badge type.")
    if badge_type == "silver":
        raise HTTPException(status_code=400, detail="Silver Premium badges are assigned automatically to active Premium members; they cannot be manually granted.")
    evidence_rules = {
        "blue": "Record the public recognition or notable work reviewed for the blue badge.",
        "purple": "Record the relevant qualifications, portfolio, or professional work reviewed for the purple badge.",
        "gold": "Record the official InnerCly role or authorization confirming this account represents InnerCly.",
        "green": "Record the business legitimacy checks reviewed, such as registration or verified business contact details.",
    }
    if active and len(reason) < 12:
        raise HTTPException(status_code=400, detail=evidence_rules[badge_type])
    target = db.scalar(select(User).where(func.lower(User.username) == username.strip().lstrip("@").lower()))
    if not target:
        raise HTTPException(status_code=404, detail="That InnerCly account could not be found.")
    row = db.scalar(select(RtAccountBadge).where(RtAccountBadge.user_id == target.id, RtAccountBadge.badge_type == badge_type))
    if row is None:
        if not active:
            return {"ok": True, "message": "No active badge needed to be removed."}
        row = RtAccountBadge(user_id=target.id, badge_type=badge_type, active=True, reason=reason, granted_by=owner.id)
        db.add(row)
    else:
        row.active = active
        row.reason = reason or row.reason
        row.granted_by = owner.id
        row.updated_at = datetime.now(timezone.utc)
    db.add(RtBadgeAudit(actor_id=owner.id, target_user_id=target.id, badge_type=badge_type, active=active, reason=reason or (row.reason if row else "")))
    db.commit()
    return {"ok": True, "message": f"{'Granted' if active else 'Removed'} {badge_type} badge {'for' if active else 'from'} @{target.username}.", "username": target.username, "badge": badge_type, "active": active}


@app.get("/api/admin/badge-audit")
def admin_badge_audit(request: Request, db: Session = Depends(get_db)) -> dict:
    require_owner(request, db)
    rows = db.scalars(select(RtBadgeAudit).order_by(RtBadgeAudit.created_at.desc(), RtBadgeAudit.id.desc()).limit(50)).all()
    ids = {r.actor_id for r in rows} | {r.target_user_id for r in rows}
    people = {u.id: u for u in db.scalars(select(User).where(User.id.in_(ids))).all()} if ids else {}
    return {"items": [{"actor": people[r.actor_id].username if r.actor_id in people else "deleted-account", "actor_badges": active_account_badges(people.get(r.actor_id)), "target": people[r.target_user_id].username if r.target_user_id in people else "deleted-account", "target_badges": active_account_badges(people.get(r.target_user_id)), "badge": r.badge_type, "active": bool(r.active), "reason": r.reason, "created_at": _rt_iso(r.created_at)} for r in rows]}


@app.get("/api/admin/verified-creators/invites")
def admin_list_verified_creator_invites(request: Request, db: Session = Depends(get_db)) -> dict:
    require_owner(request, db)
    rows = db.scalars(select(RtVerifiedCreatorInvite).order_by(RtVerifiedCreatorInvite.created_at.desc()).limit(200)).all()
    ids = {r.user_id for r in rows} | {r.invited_by for r in rows}
    people = {u.id: u for u in db.scalars(select(User).where(User.id.in_(ids))).all()} if ids else {}
    return {"items": [{"username": people[r.user_id].username if r.user_id in people else "deleted-account", "badges": active_account_badges(people.get(r.user_id)), "invited_by": people[r.invited_by].username if r.invited_by in people else "deleted-account", "invited_by_badges": active_account_badges(people.get(r.invited_by)), "created_at": _rt_iso(r.created_at)} for r in rows]}


@app.post("/api/admin/verified-creators/invites", status_code=status.HTTP_201_CREATED)
def admin_invite_verified_creator(body: dict, request: Request, db: Session = Depends(get_db)) -> dict:
    owner = require_owner(request, db)
    require_same_origin(request)
    username = str(body.get("username", "")).strip().lstrip("@").lower()
    target = db.scalar(select(User).where(func.lower(User.username) == username)) if username else None
    if not target:
        raise HTTPException(status_code=404, detail="Enter an existing InnerCly username.")
    row = db.scalar(select(RtVerifiedCreatorInvite).where(RtVerifiedCreatorInvite.user_id == target.id))
    if row is None:
        db.add(RtVerifiedCreatorInvite(user_id=target.id, invited_by=owner.id))
        _rt_notify(db, target.id, "You have been invited to the private Verified Creators group.", "verified_creators", target.id)
        db.commit()
    return {"ok": True, "message": f"@{target.username} can now access Verified Creators."}


@app.delete("/api/admin/verified-creators/invites/{username}")
def admin_remove_verified_creator_invite(username: str, request: Request, db: Session = Depends(get_db)) -> dict:
    owner = require_owner(request, db)
    require_same_origin(request)
    target = db.scalar(select(User).where(func.lower(User.username) == username.strip().lstrip("@").lower()))
    if not target:
        raise HTTPException(status_code=404, detail="That InnerCly account could not be found.")
    row = db.scalar(select(RtVerifiedCreatorInvite).where(RtVerifiedCreatorInvite.user_id == target.id))
    if row:
        db.delete(row)
        db.commit()
    return {"ok": True, "message": f"Removed @{target.username} from the private Verified Creators group."}



# ---- Premium, Kilos, creator earnings, and monetization ----
MONEY_QUANT = Decimal("0.01")
VERIFIED_PREMIUM_BADGES = {"blue", "purple", "gold", "green"}
PROFILE_THEMES = {"ice", "lavender", "mint", "sunset", "midnight"}
CHAT_THEMES = {"ice", "lavender", "mint"}
STORY_EFFECTS = {"normal", "vivid", "bw", "warm", "cool", "neon", "dreamy", "film"}


def _money(value) -> Decimal:
    try:
        return Decimal(str(value or "0")).quantize(MONEY_QUANT)
    except (InvalidOperation, ValueError, TypeError):
        return Decimal("0.00")


def _round_money(value: Decimal) -> Decimal:
    return value.quantize(MONEY_QUANT)


def _has_verified_premium(user: User) -> bool:
    return any(b.active and b.badge_type in VERIFIED_PREMIUM_BADGES for b in user.account_badges)


def _premium_source(user: User) -> str:
    if (user.role or "member").lower() == "owner":
        return "owner"
    if _has_verified_premium(user):
        return "verified"
    if user_has_premium(user):
        return "subscription"
    return "none"


def _ensure_kilos_wallet(db: Session, user_id: int, for_update: bool = False) -> RtKilosWallet:
    statement = select(RtKilosWallet).where(RtKilosWallet.user_id == user_id)
    if for_update:
        statement = statement.with_for_update()
    wallet = db.scalar(statement)
    if wallet is None:
        wallet = RtKilosWallet(user_id=user_id, balance=0)
        db.add(wallet)
        db.flush()
    return wallet


def _ensure_creator_wallet(db: Session, user_id: int, for_update: bool = False) -> RtCreatorWallet:
    statement = select(RtCreatorWallet).where(RtCreatorWallet.user_id == user_id)
    if for_update:
        statement = statement.with_for_update()
    wallet = db.scalar(statement)
    if wallet is None:
        wallet = RtCreatorWallet(user_id=user_id, available_usd=Decimal("0.00"))
        db.add(wallet)
        db.flush()
    return wallet


def _premium_preferences(db: Session, user_id: int) -> RtPremiumPreferences:
    prefs = db.scalar(select(RtPremiumPreferences).where(RtPremiumPreferences.user_id == user_id))
    if prefs is None:
        prefs = RtPremiumPreferences(user_id=user_id)
        db.add(prefs)
        db.flush()
    return prefs


def _stripe_request(path: str, fields: dict[str, str]) -> dict:
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Payments aren't enabled yet. The Owner must configure Stripe on the hosting service first.")
    data = urlencode(fields).encode("utf-8")
    req = UrlRequest(
        "https://api.stripe.com/v1/" + path.lstrip("/"),
        data=data,
        headers={"Authorization": "Bearer " + STRIPE_SECRET_KEY, "Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=18) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        try:
            body = json.loads(exc.read().decode("utf-8"))
            detail = body.get("error", {}).get("message", "Payment provider rejected the request.")
        except Exception:
            detail = "Payment provider rejected the request."
        print(f"[InnerCly payments] Stripe checkout rejected: {detail}")
        raise HTTPException(status_code=502, detail="Payment setup couldn't start. Please try again later.") from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"[InnerCly payments] Stripe connection failed: {type(exc).__name__}")
        raise HTTPException(status_code=502, detail="Payment provider could not be reached. No payment was taken.") from exc


def _stripe_get(path: str) -> dict:
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=503, detail="Payment processing is not configured yet.")
    req = UrlRequest(
        "https://api.stripe.com/v1/" + path.lstrip("/"),
        headers={"Authorization": "Bearer " + STRIPE_SECRET_KEY},
        method="GET",
    )
    try:
        with urlopen(req, timeout=18) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        print(f"[InnerCly payments] Stripe transaction lookup rejected: HTTP {exc.code}")
        raise HTTPException(status_code=503, detail="The card-processing fee could not be verified yet. Stripe will retry the payment notification.") from exc
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"[InnerCly payments] Stripe fee lookup failed: {type(exc).__name__}")
        raise HTTPException(status_code=503, detail="The card-processing fee could not be verified yet. Stripe will retry the payment notification.") from exc


def _stripe_actual_payment_fee(session_obj: dict) -> Decimal:
    """Get the actual Stripe balance-transaction fee for a completed USD Checkout payment."""
    payment_intent = session_obj.get("payment_intent")
    if isinstance(payment_intent, dict):
        intent = payment_intent
    elif payment_intent:
        intent = _stripe_get("payment_intents/" + quote(str(payment_intent), safe="") + "?expand%5B%5D=latest_charge.balance_transaction")
    else:
        raise HTTPException(status_code=503, detail="Stripe has not exposed the successful payment transaction yet. The webhook can retry.")
    charge = intent.get("latest_charge")
    if isinstance(charge, str):
        charge = _stripe_get("charges/" + quote(charge, safe="") + "?expand%5B%5D=balance_transaction")
    if not isinstance(charge, dict):
        raise HTTPException(status_code=503, detail="Stripe has not exposed the successful charge yet. The webhook can retry.")
    transaction = charge.get("balance_transaction")
    if isinstance(transaction, str):
        transaction = _stripe_get("balance_transactions/" + quote(transaction, safe=""))
    if not isinstance(transaction, dict) or not isinstance(transaction.get("fee"), int):
        raise HTTPException(status_code=503, detail="Stripe has not returned the exact processing fee yet. The webhook can retry.")
    if str(transaction.get("currency", "")).lower() != "usd":
        raise HTTPException(status_code=503, detail="Marketplace checkout fee reconciliation currently expects USD transactions.")
    return _round_money(Decimal(transaction["fee"]) / Decimal("100"))


def _create_checkout(db: Session, request: Request, user: User, kind: str, product_key: str,
                     amount: Decimal, product_name: str, kilos_quantity: int = 0,
                     currency_code: str = "USD", listing_id: Optional[int] = None,
                     seller_user_id: Optional[int] = None) -> dict:
    if not STRIPE_SECRET_KEY or not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Payments aren't enabled yet. The Owner must configure both Stripe keys and verify the webhook endpoint before purchases can begin.")
    currency_code = (currency_code or "USD").strip().upper()
    if currency_code != "USD":
        raise HTTPException(status_code=422, detail="Secure marketplace checkout currently supports USD-priced listings only. Other currency listings can still use the existing seller-message and delivery-request flow.")
    payment = RtCheckoutPayment(
        user_id=user.id, payment_kind=kind, product_key=product_key,
        amount_usd=_round_money(amount), kilos_quantity=kilos_quantity, listing_id=listing_id,
        seller_user_id=seller_user_id, currency_code=currency_code, status="pending"
    )
    db.add(payment)
    db.commit()
    db.refresh(payment)
    root = str(request.base_url).rstrip("/")
    fields = {
        "mode": "payment",
        "success_url": root + ("/?payment=success#marketplace" if kind == "marketplace" else "/?payment=success#premium"),
        "cancel_url": root + ("/?payment=cancel#marketplace" if kind == "marketplace" else "/?payment=cancel#premium"),
        "client_reference_id": str(payment.id),
        "line_items[0][quantity]": "1",
        "line_items[0][price_data][currency]": currency_code.lower(),
        "line_items[0][price_data][unit_amount]": str(int((_round_money(amount) * 100).to_integral_value())),
        "line_items[0][price_data][product_data][name]": product_name,
        "line_items[0][price_data][product_data][description]": "InnerCly digital product; virtual credits are not cash and are not directly redeemable by buyers.",
        "metadata[payment_id]": str(payment.id),
        "metadata[kind]": kind,
        "metadata[product_key]": product_key,
        "metadata[user_id]": str(user.id),
        "metadata[kilos_quantity]": str(kilos_quantity),
        "metadata[listing_id]": str(listing_id or ""),
        "metadata[seller_user_id]": str(seller_user_id or ""),
        "payment_intent_data[metadata][payment_id]": str(payment.id),
        "payment_intent_data[metadata][kind]": kind,
        "payment_intent_data[metadata][user_id]": str(user.id),
        "payment_intent_data[metadata][listing_id]": str(listing_id or ""),
        "payment_intent_data[metadata][seller_user_id]": str(seller_user_id or ""),
    }
    if kind == "premium":
        fields["line_items[0][price_data][product_data][description]"] = ("InnerCly lifetime feature access, ad-removal and community cosmetics; 50GB cloud storage cap. Third-party marketplace purchases are separate." if product_key in LIFETIME_PLAN_CODES else "InnerCly Premium membership access for the selected billing period.")
    try:
        session_data = _stripe_request("checkout/sessions", fields)
        if not session_data.get("id") or not session_data.get("url"):
            raise HTTPException(status_code=502, detail="Payment provider didn't return a checkout link. No payment was taken.")
        payment.stripe_checkout_session_id = str(session_data["id"])
        db.commit()
        return {"checkout_url": session_data["url"], "payment_id": payment.id}
    except Exception:
        db.rollback()
        try:
            row = db.get(RtCheckoutPayment, payment.id)
            if row and row.status == "pending":
                row.status = "failed"
                db.commit()
        except Exception:
            db.rollback()
        raise


def _record_monetization(db: Session, record_type: str, gross: Decimal, processor_fee: Decimal,
                         platform_commission: Decimal, creator_amount: Decimal,
                         actor_user_id: Optional[int] = None, creator_user_id: Optional[int] = None,
                         reference: str = "", note: str = "") -> RtMonetizationRecord:
    row = RtMonetizationRecord(
        record_type=record_type, actor_user_id=actor_user_id, creator_user_id=creator_user_id,
        gross_amount_usd=_round_money(gross), processing_fee_usd=_round_money(processor_fee),
        platform_commission_usd=_round_money(platform_commission), creator_amount_usd=_round_money(creator_amount),
        currency_code="USD", reference=reference[:180], note=note[:500]
    )
    db.add(row)
    return row


def _apply_checkout_completion(db: Session, session_obj: dict) -> None:
    session_id = str(session_obj.get("id") or "")
    if not session_id or session_obj.get("payment_status") not in {"paid", "no_payment_required"}:
        return
    payment = db.scalar(select(RtCheckoutPayment).where(RtCheckoutPayment.stripe_checkout_session_id == session_id).with_for_update())
    if payment is None:
        metadata = session_obj.get("metadata") or {}
        try:
            payment_id = int(metadata.get("payment_id") or session_obj.get("client_reference_id") or 0)
        except (TypeError, ValueError):
            payment_id = 0
        payment = db.scalar(select(RtCheckoutPayment).where(RtCheckoutPayment.id == payment_id).with_for_update()) if payment_id else None
    if payment is None or payment.status == "paid":
        return
    if payment.user_id != int((session_obj.get("metadata") or {}).get("user_id", payment.user_id)):
        return
    now = datetime.now(timezone.utc)
    user = db.get(User, payment.user_id)
    if not user:
        return
    # Reconcile the exact Stripe balance-transaction fee for every USD checkout
    # before granting digital goods or recording platform revenue. If the fee is
    # not ready, return 503 so Stripe retries instead of writing incomplete books.
    processing_fee = _stripe_actual_payment_fee(session_obj)
    payment.status = "paid"
    payment.stripe_checkout_session_id = session_id
    payment.paid_at = now
    if payment.payment_kind == "premium":
        current = db.scalar(select(RtPremiumSubscription).where(RtPremiumSubscription.user_id == user.id))
        plan = payment.product_key
        if current is None:
            current = RtPremiumSubscription(user_id=user.id, plan_code=plan, status="active", started_at=now)
            db.add(current)
        if current.plan_code not in LIFETIME_PLAN_CODES or plan in LIFETIME_PLAN_CODES:
            if plan in LIFETIME_PLAN_CODES:
                current.plan_code = "lifetime"
                current.status = "active"
                current.expires_at = None
                current.started_at = now
            else:
                old_expiry = current.expires_at
                if current.status == "active" and old_expiry is not None and old_expiry.tzinfo is None:
                    old_expiry = old_expiry.replace(tzinfo=timezone.utc)
                start_from = old_expiry if current.status == "active" and old_expiry and old_expiry > now else now
                current.plan_code = plan
                current.status = "active"
                current.started_at = now
                current.expires_at = start_from + timedelta(days=PREMIUM_PLAN_DAYS[plan])
            current.stripe_checkout_session_id = session_id
            current.updated_at = now
        _record_monetization(db, "premium_sale", payment.amount_usd, processing_fee, payment.amount_usd,
                             Decimal("0.00"), actor_user_id=user.id, reference=session_id,
                             note=f"Premium {plan} pass. Gross revenue and exact Stripe processing fee recorded separately; lifetime storage cap is 50GB." if plan in LIFETIME_PLAN_CODES else f"Premium {plan} pass. Gross revenue and exact Stripe processing fee recorded separately.")
    elif payment.payment_kind == "kilos":
        wallet = _ensure_kilos_wallet(db, user.id)
        wallet.balance += payment.kilos_quantity
        wallet.updated_at = now
        db.add(RtKilosLedger(user_id=user.id, transaction_type="purchase", delta_kilos=payment.kilos_quantity,
                             balance_after=wallet.balance, reference_type="checkout", reference_id=payment.id,
                             note=f"Purchased {payment.kilos_quantity:,} Kilos."))
        nominal_value = _round_money(Decimal(payment.kilos_quantity) / Decimal("1000") * KILOS_FACE_VALUE_USD_PER_1000)
        # Margin is built into each pack's listed price; no credits are secretly removed from the wallet.
        included_margin = max(Decimal("0.00"), payment.amount_usd - nominal_value)
        _record_monetization(db, "kilos_sale", payment.amount_usd, processing_fee, included_margin,
                             Decimal("0.00"), actor_user_id=user.id, reference=session_id,
                             note=f"Credited all {payment.kilos_quantity:,} purchased Kilos. Pack margin is before the separately recorded Stripe processing fee.")
    elif payment.payment_kind == "marketplace":
        if not payment.listing_id or not payment.seller_user_id:
            raise HTTPException(status_code=503, detail="Marketplace sale details are incomplete; Stripe will retry the payment notification.")
        listing = db.scalar(select(RtListing).where(RtListing.id == payment.listing_id).with_for_update())
        seller = db.get(User, payment.seller_user_id)
        if not listing or not seller or listing.seller_id != seller.id:
            raise HTTPException(status_code=503, detail="Marketplace seller or listing could not be verified; Stripe will retry the payment notification.")
        listing_type = (getattr(listing, "listing_type", "physical") or "physical").lower()
        base_rate = DIGITAL_MARKETPLACE_COMMISSION_RATE if listing_type == "digital" else PHYSICAL_MARKETPLACE_COMMISSION_RATE
        exclusive_hub = (seller.username or "").lower() in EXCLUSIVE_SUBSCRIPTION_HUB_USERNAMES
        commission_rate = base_rate * Decimal("0.50") if exclusive_hub else base_rate
        commission = _round_money(payment.amount_usd * commission_rate)
        seller_amount = _round_money(payment.amount_usd - processing_fee - commission)
        if seller_amount < Decimal("0.00"):
            raise HTTPException(status_code=503, detail="The sale is waiting for manual review because card costs exceed the seller proceeds.")
        wallet = _ensure_creator_wallet(db, seller.id, for_update=True)
        wallet.available_usd = _round_money(wallet.available_usd + seller_amount)
        wallet.updated_at = now
        listing.status = "Sold"
        conversation = db.scalar(select(RtMarketConversation).where(RtMarketConversation.listing_id == listing.id, RtMarketConversation.buyer_id == user.id))
        if not conversation:
            conversation = RtMarketConversation(listing_id=listing.id, buyer_id=user.id, seller_id=seller.id)
            db.add(conversation)
            db.flush()
        _record_monetization(db, "marketplace_sale", payment.amount_usd, processing_fee, commission, seller_amount,
                             actor_user_id=user.id, creator_user_id=seller.id, reference=session_id,
                             note=f"Automated USD Marketplace checkout ({listing_type} goods). Seller proceeds = gross less exact Stripe fee and {commission_rate * 100}% InnerCly commission{' after exclusive subscription-hub discount' if exclusive_hub else ''}.")
        _rt_notify(db, user.id, f"Your payment for {listing.title} was successful. Message the seller to arrange delivery or fulfilment.", "market_conversation", conversation.id)
        _rt_notify(db, seller.id, f"Your Marketplace listing {listing.title} was purchased. Contact the buyer to arrange delivery or fulfilment.", "market_conversation", conversation.id)
    db.commit()


@app.get("/api/premium/overview")
def premium_overview(request: Request, db: Session = Depends(get_db)) -> dict:
    user = require_rt_user(request, db)
    premium = user_has_premium(user)
    source = _premium_source(user)
    subscription = db.scalar(select(RtPremiumSubscription).where(RtPremiumSubscription.user_id == user.id))
    kilos_wallet = db.scalar(select(RtKilosWallet).where(RtKilosWallet.user_id == user.id))
    creator_wallet = db.scalar(select(RtCreatorWallet).where(RtCreatorWallet.user_id == user.id))
    prefs = _premium_preferences(db, user.id)
    db.commit()
    return {
        "premium": premium, "premium_source": source,
        "verified_badges": [b.badge_type for b in user.account_badges if b.active and b.badge_type in VERIFIED_PREMIUM_BADGES],
        "subscription": {"plan": subscription.plan_code, "status": subscription.status, "started_at": _rt_iso(subscription.started_at), "expires_at": _rt_iso(subscription.expires_at)} if subscription else None,
        "payments_configured": bool(STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET),
        "kilos_balance": kilos_wallet.balance if kilos_wallet else 0,
        "creator_earnings_usd": format(_money(creator_wallet.available_usd if creator_wallet else 0), ".2f"),
        "kilos_packs": [{"key": k, "label": v["label"], "kilos": v["kilos"], "price_usd": format(v["price"], ".2f")} for k,v in KILOS_PACKS.items()],
        "plans": [{"key": k, "price_usd": format(v, ".2f"), "duration_days": PREMIUM_PLAN_DAYS[k], "label": {"monthly":"Monthly", "annual":"Annual", "lifetime":"Lifetime", "founding_lifetime":"Founding Member Lifetime"}[k], "description": {"monthly":"Premium access for 30 days.", "annual":"Premium access for 365 days — save versus monthly.", "lifetime":"One-time access to eligible features, ad-removal and community cosmetics; 50GB cloud storage cap.", "founding_lifetime":"Limited to the first 500 founding members; lifetime feature access, ad-removal and community cosmetics; 50GB cloud storage cap."}[k]} for k,v in PREMIUM_PLAN_PRICES.items()],
        "founding_members": {"limit": FOUNDING_MEMBER_LIMIT, "claimed": int(db.scalar(select(func.count(RtCheckoutPayment.id)).where(RtCheckoutPayment.payment_kind == "premium", RtCheckoutPayment.product_key == "founding_lifetime", RtCheckoutPayment.status == "paid")) or 0)},
        "monetization_policy": {"standard_creator_share_percent": 80, "early_adopter_creator_share_percent": 90, "early_adopter_months": 12, "digital_marketplace_fee_percent": 10, "physical_marketplace_fee_percent": 5, "exclusive_hub_fee_discount_percent": 50, "lifetime_storage_cap_gb": 50, "founding_member_limit": FOUNDING_MEMBER_LIMIT},
        "preferences": {"profile_theme": prefs.profile_theme, "story_effect": prefs.story_effect, "chat_theme": prefs.chat_theme, "early_access_enabled": bool(prefs.early_access_enabled)},
        "commission_policy": {"kilos_creator_share_percent": 80, "kilos_platform_share_percent": 20, "early_adopter_creator_share_percent": 90, "early_adopter_months": 12, "ad_creator_share_percent": 55, "ad_owner_share_percent": 45, "digital_marketplace_platform_percent": 10, "physical_marketplace_platform_percent": 5, "exclusive_hub_marketplace_fee_discount_percent": 50, "lifetime_storage_cap_gb": 50, "kilos_per_usd_face_value": 1000},
    }


@app.post("/api/premium/checkout")
def premium_checkout(body: PremiumCheckoutBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    plan = body.plan.strip().lower()
    if plan not in PREMIUM_PLAN_PRICES:
        raise HTTPException(status_code=422, detail="Choose a valid Premium plan.")
    if plan == "founding_lifetime":
        claimed = int(db.scalar(select(func.count(RtCheckoutPayment.id)).where(RtCheckoutPayment.payment_kind == "premium", RtCheckoutPayment.product_key == "founding_lifetime", RtCheckoutPayment.status.in_(["paid", "pending"]))) or 0)
        if claimed >= FOUNDING_MEMBER_LIMIT:
            raise HTTPException(status_code=409, detail="The first 500 Founding Member lifetime passes have been claimed.")
    if _has_verified_premium(user) or (user.role or "member").lower() == "owner":
        raise HTTPException(status_code=400, detail="Your active verification already includes Premium at no charge.")
    subscription = db.scalar(select(RtPremiumSubscription).where(RtPremiumSubscription.user_id == user.id))
    if subscription and subscription.status == "active" and subscription.plan_code in LIFETIME_PLAN_CODES and user_has_premium(user):
        raise HTTPException(status_code=400, detail="Your lifetime Premium access is already active. No further subscription payment is needed.")
    return _create_checkout(db, request, user, "premium", plan, PREMIUM_PLAN_PRICES[plan], f"InnerCly Premium — { {'monthly':'Monthly','annual':'Annual','lifetime':'Lifetime','founding_lifetime':'Founding Member Lifetime'}[plan] }")


@app.post("/api/kilos/checkout")
def kilos_checkout(body: KilosCheckoutBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    key = body.pack.strip().lower()
    pack = KILOS_PACKS.get(key)
    if not pack:
        raise HTTPException(status_code=422, detail="Choose a valid Kilos pack.")
    return _create_checkout(db, request, user, "kilos", key, pack["price"], f"InnerCly Kilos — {pack['kilos']:,} credits", int(pack["kilos"]))


@app.post("/api/payments/stripe/webhook")
async def stripe_webhook(request: Request, stripe_signature: Optional[str] = None, db: Session = Depends(get_db)) -> dict:
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=503, detail="Stripe webhook signing secret is not configured.")
    signature = stripe_signature or request.headers.get("Stripe-Signature", "")
    raw = await request.body()
    parts = {}
    for segment in signature.split(","):
        if "=" in segment:
            key, value = segment.split("=", 1)
            parts.setdefault(key, []).append(value)
    try:
        timestamp = int(parts.get("t", ["0"])[0])
        provided = parts.get("v1", [])
        signed = str(timestamp).encode("ascii") + b"." + raw
        expected = hmac.new(STRIPE_WEBHOOK_SECRET.encode("utf-8"), signed, hashlib.sha256).hexdigest()
        if not timestamp or abs(int(datetime.now(timezone.utc).timestamp()) - timestamp) > 300 or not any(hmac.compare_digest(expected, candidate) for candidate in provided):
            raise HTTPException(status_code=400, detail="Invalid Stripe webhook signature.")
        event = json.loads(raw.decode("utf-8"))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Invalid Stripe webhook payload.") from exc
    event_type = event.get("type")
    session_obj = (event.get("data") or {}).get("object") or {}
    if event_type in {"checkout.session.completed", "checkout.session.async_payment_succeeded"}:
        _apply_checkout_completion(db, session_obj)
    elif event_type in {"checkout.session.expired", "checkout.session.async_payment_failed"}:
        session_id = str(session_obj.get("id") or "")
        if session_id:
            payment = db.scalar(select(RtCheckoutPayment).where(RtCheckoutPayment.stripe_checkout_session_id == session_id).with_for_update())
            if payment and payment.status == "pending":
                payment.status = "expired" if event_type == "checkout.session.expired" else "failed"
                db.commit()
    return {"received": True}


@app.get("/api/premium/creator-analytics")
def premium_creator_analytics(request: Request, db: Session = Depends(get_db)) -> dict:
    user = require_rt_user(request, db)
    if not user_has_premium(user):
        raise HTTPException(status_code=403, detail="Creator Growth Studio is a Premium feature. Verified accounts get it free.")
    post_count = db.scalar(select(func.count(RtPost.id)).where(RtPost.author_id == user.id)) or 0
    post_views = db.scalar(select(func.count(RtPostView.id)).select_from(RtPostView).join(RtPost, RtPost.id == RtPostView.post_id).where(RtPost.author_id == user.id)) or 0
    likes = db.scalar(select(func.count(RtPostLike.id)).select_from(RtPostLike).join(RtPost, RtPost.id == RtPostLike.post_id).where(RtPost.author_id == user.id)) or 0
    comments = db.scalar(select(func.count(RtPostComment.id)).select_from(RtPostComment).join(RtPost, RtPost.id == RtPostComment.post_id).where(RtPost.author_id == user.id)) or 0
    followers = db.scalar(select(func.count(RtUserFollow.id)).where(RtUserFollow.following_id == user.id)) or 0
    return {"posts": int(post_count), "views": int(post_views), "likes": int(likes), "comments": int(comments), "followers": int(followers), "note": "Views use the app's daily per-viewer counter; they aren't total watch time or ad impressions."}


@app.put("/api/premium/preferences")
def update_premium_preferences(body: PremiumPreferencesBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    if not user_has_premium(user):
        raise HTTPException(status_code=403, detail="Premium profile themes, Story effects and chat themes require Premium. Verified accounts get access free.")
    theme = body.profile_theme.strip().lower()
    effect = body.story_effect.strip().lower()
    chat_theme = body.chat_theme.strip().lower()
    if theme not in PROFILE_THEMES or effect not in STORY_EFFECTS or chat_theme not in CHAT_THEMES:
        raise HTTPException(status_code=422, detail="Choose one of the available Premium themes or Story effects.")
    prefs = _premium_preferences(db, user.id)
    prefs.profile_theme = theme
    prefs.story_effect = effect
    prefs.chat_theme = chat_theme
    prefs.early_access_enabled = True
    db.commit()
    return {"ok": True, "preferences": {"profile_theme": theme, "story_effect": effect, "chat_theme": chat_theme, "early_access_enabled": True}}


@app.get("/api/kilos/ledger")
def kilos_ledger(request: Request, db: Session = Depends(get_db)) -> dict:
    user = require_rt_user(request, db)
    wallet = db.scalar(select(RtKilosWallet).where(RtKilosWallet.user_id == user.id))
    rows = db.scalars(select(RtKilosLedger).where(RtKilosLedger.user_id == user.id).order_by(RtKilosLedger.created_at.desc(), RtKilosLedger.id.desc()).limit(40)).all()
    return {"balance": wallet.balance if wallet else 0, "items": [{"id": r.id, "type": r.transaction_type, "delta_kilos": r.delta_kilos, "balance_after": r.balance_after, "note": r.note, "created_at": _rt_iso(r.created_at)} for r in rows]}


@app.post("/api/kilos/gift", status_code=status.HTTP_201_CREATED)
def kilos_gift(body: KilosGiftBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    sender = require_rt_user(request, db)
    stream = db.get(RtLiveStream, body.stream_id)
    if not stream or stream.status != "live":
        raise HTTPException(status_code=404, detail="That live stream is no longer active.")
    creator = db.get(User, stream.host_id)
    if not creator or creator.id == sender.id:
        raise HTTPException(status_code=400, detail="You can't send a gift to yourself.")
    requested_username = body.creator_username.strip().lstrip("@").lower()
    if creator.username.lower() != requested_username:
        raise HTTPException(status_code=409, detail="The selected streamer doesn't match this live stream. Refresh and try again.")
    sender_wallet = _ensure_kilos_wallet(db, sender.id, for_update=True)
    if sender_wallet.balance < body.kilos:
        db.rollback()
        raise HTTPException(status_code=400, detail="You don't have enough Kilos. Purchase a pack first.")
    sender_wallet.balance -= body.kilos
    sender_wallet.updated_at = datetime.now(timezone.utc)
    gross = _round_money(Decimal(body.kilos) / Decimal("1000") * KILOS_FACE_VALUE_USD_PER_1000)
    creator_created = creator.created_at
    if creator_created and creator_created.tzinfo is None:
        creator_created = creator_created.replace(tzinfo=timezone.utc)
    early_adopter = (creator.username or "").lower() in EARLY_ADOPTER_USERNAMES and creator_created is not None and (datetime.now(timezone.utc) - creator_created).days < 365
    creator_share = EARLY_ADOPTER_CREATOR_SHARE if early_adopter else KILOS_CREATOR_SHARE
    creator_amount = _round_money(gross * creator_share)
    platform_share = _round_money(gross - creator_amount)
    creator_wallet = _ensure_creator_wallet(db, creator.id, for_update=True)
    creator_wallet.available_usd = _round_money(creator_wallet.available_usd + creator_amount)
    creator_wallet.updated_at = datetime.now(timezone.utc)
    db.add(RtKilosLedger(user_id=sender.id, related_user_id=creator.id, transaction_type="gift_sent", delta_kilos=-body.kilos,
                         balance_after=sender_wallet.balance, reference_type="live_stream", reference_id=stream.id,
                         note=f"Sent {body.kilos:,} Kilos to @{creator.username} during a live stream."))
    _record_monetization(db, "kilos_gift", gross, Decimal("0.00"), platform_share, creator_amount,
                         actor_user_id=sender.id, creator_user_id=creator.id, reference=f"stream:{stream.id}",
                         note=f"{body.kilos:,} Kilos gifted. Creator receives {creator_share * 100}% of the defined gift value; InnerCly share is { (Decimal(1) - creator_share) * 100 }%.")
    _rt_notify(db, creator.id, f"@{sender.username} sent you {body.kilos:,} Kilos during your live stream.", "live_stream", stream.id)
    db.commit()
    return {"ok": True, "kilos_remaining": sender_wallet.balance, "gifted_kilos": body.kilos, "creator_earnings_usd": format(creator_amount, ".2f"), "message": f"Sent {body.kilos:,} Kilos to @{creator.username}."}


@app.get("/api/creator/earnings")
def creator_earnings(request: Request, db: Session = Depends(get_db)) -> dict:
    user = require_rt_user(request, db)
    wallet = db.scalar(select(RtCreatorWallet).where(RtCreatorWallet.user_id == user.id))
    payouts = db.scalars(select(RtCreatorPayoutRequest).where(RtCreatorPayoutRequest.creator_user_id == user.id).order_by(RtCreatorPayoutRequest.created_at.desc()).limit(20)).all()
    records = db.scalars(select(RtMonetizationRecord).where(RtMonetizationRecord.creator_user_id == user.id).order_by(RtMonetizationRecord.created_at.desc()).limit(20)).all()
    return {"available_usd": format(_money(wallet.available_usd if wallet else 0), ".2f"), "minimum_payout_usd": "10.00", "payouts": [{"id": p.id, "amount_usd": format(_money(p.amount_usd), ".2f"), "status": p.status, "note": p.payout_note, "created_at": _rt_iso(p.created_at)} for p in payouts], "earnings": [{"type": r.record_type, "gross_usd": format(_money(r.gross_amount_usd), ".2f"), "creator_usd": format(_money(r.creator_amount_usd), ".2f"), "created_at": _rt_iso(r.created_at)} for r in records]}


@app.post("/api/creator/payout-requests", status_code=status.HTTP_201_CREATED)
def creator_payout_request(body: CreatorPayoutBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    amount = _money(body.amount_usd)
    if amount < Decimal("10.00"):
        raise HTTPException(status_code=422, detail="The minimum payout request is $10.00 USD.")
    wallet = _ensure_creator_wallet(db, user.id, for_update=True)
    if amount > _money(wallet.available_usd):
        db.rollback()
        raise HTTPException(status_code=400, detail="Your available creator earnings are too low for that payout request.")
    wallet.available_usd = _round_money(wallet.available_usd - amount)
    wallet.updated_at = datetime.now(timezone.utc)
    row = RtCreatorPayoutRequest(creator_user_id=user.id, amount_usd=amount, status="pending", payout_note=body.payout_note.strip())
    db.add(row)
    db.commit(); db.refresh(row)
    return {"ok": True, "id": row.id, "status": row.status, "available_usd": format(wallet.available_usd, ".2f"), "message": "Payout request submitted. It is reserved for Owner review; no payout is sent automatically by this request."}


@app.get("/api/live/streams")
def list_live_streams(request: Request, db: Session = Depends(get_db)) -> dict:
    user = require_rt_user(request, db)
    rows = db.scalars(select(RtLiveStream).where(RtLiveStream.status == "live").order_by(RtLiveStream.started_at.desc()).limit(100)).all()
    items = []
    for row in rows:
        host = db.get(User, row.host_id)
        if not host:
            continue
        room = _LIVE_ROOMS.get(row.id, {}) if "_LIVE_ROOMS" in globals() else {}
        viewers = sum(1 for peer in room.values() if peer.get("role") == "viewer")
        items.append({"id": row.id, "title": row.title, "started_at": _rt_iso(row.started_at), "host": _rt_user(host), "viewer_count": viewers, "is_mine": row.host_id == user.id, "show_in_feed": bool(row.show_in_feed)})
    return {"items": items}


@app.post("/api/live/streams", status_code=status.HTTP_201_CREATED)
def start_live_stream(body: dict, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    title = str(body.get("title", "")).strip()[:120]
    show_in_feed = bool(body.get("show_in_feed", False))
    if len(title) < 3:
        raise HTTPException(status_code=422, detail="Give your live stream a title of at least 3 characters.")
    existing = db.scalar(select(RtLiveStream).where(RtLiveStream.host_id == user.id, RtLiveStream.status == "live"))
    if existing:
        existing.title = title
        existing.show_in_feed = show_in_feed
        db.commit()
        return {"item": {"id": existing.id, "title": existing.title, "started_at": _rt_iso(existing.started_at), "host": _rt_user(user), "viewer_count": 0, "is_mine": True, "show_in_feed": bool(existing.show_in_feed)}}
    row = RtLiveStream(host_id=user.id, title=title, status="live", show_in_feed=show_in_feed)
    db.add(row); db.commit(); db.refresh(row)
    _rt_notify(db, user.id, "Your InnerCly Live session was created. Allow camera and microphone access to start streaming.", "live_stream", row.id)
    db.commit()
    return {"item": {"id": row.id, "title": row.title, "started_at": _rt_iso(row.started_at), "host": _rt_user(user), "viewer_count": 0, "is_mine": True, "show_in_feed": bool(row.show_in_feed)}}


@app.patch("/api/live/streams/{stream_id}")
def update_live_stream(stream_id: int, body: dict, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    row = db.get(RtLiveStream, stream_id)
    if not row or row.status != "live":
        raise HTTPException(status_code=404, detail="That live stream is no longer active.")
    if row.host_id != user.id and (user.role or "member").lower() != "owner":
        raise HTTPException(status_code=403, detail="Only the streamer can change live feed visibility.")
    if "show_in_feed" in body:
        row.show_in_feed = bool(body.get("show_in_feed"))
    db.commit()
    return {"ok": True, "id": row.id, "show_in_feed": bool(row.show_in_feed), "message": "Your live stream will appear in Home feed." if row.show_in_feed else "Your live stream is hidden from Home feed."}


@app.delete("/api/live/streams/{stream_id}")
def stop_live_stream(stream_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    row = db.get(RtLiveStream, stream_id)
    if not row:
        raise HTTPException(status_code=404, detail="Live stream not found.")
    if row.host_id != user.id and (user.role or "member").lower() != "owner":
        raise HTTPException(status_code=403, detail="Only the streamer can end this live session.")
    row.status = "ended"
    row.ended_at = datetime.now(timezone.utc)
    db.commit()
    return {"ok": True}


@app.get("/api/admin/monetization")
def admin_monetization_overview(request: Request, db: Session = Depends(get_db)) -> dict:
    require_owner(request, db)
    def amount(col, condition=None) -> Decimal:
        q = select(func.coalesce(func.sum(col), 0))
        if condition is not None:
            q = q.where(condition)
        return _money(db.scalar(q) or 0)
    def total(col, condition=None):
        return format(amount(col, condition), ".2f")
    premium_gross = amount(RtMonetizationRecord.gross_amount_usd, RtMonetizationRecord.record_type == "premium_sale")
    premium_fee = amount(RtMonetizationRecord.processing_fee_usd, RtMonetizationRecord.record_type == "premium_sale")
    kilos_margin = amount(RtMonetizationRecord.platform_commission_usd, RtMonetizationRecord.record_type == "kilos_sale")
    kilos_fee = amount(RtMonetizationRecord.processing_fee_usd, RtMonetizationRecord.record_type == "kilos_sale")
    gift_share = amount(RtMonetizationRecord.platform_commission_usd, RtMonetizationRecord.record_type == "kilos_gift")
    owner_ad_share = amount(RtMonetizationRecord.platform_commission_usd, RtMonetizationRecord.record_type == "ad_revenue")
    marketplace_share = amount(RtMonetizationRecord.platform_commission_usd, RtMonetizationRecord.record_type == "marketplace_sale")
    # Marketplace processing fees are deducted from seller proceeds, separately from the applicable platform commission.
    estimated_owner_net = premium_gross - premium_fee + kilos_margin - kilos_fee + gift_share + owner_ad_share + marketplace_share
    records = db.scalars(select(RtMonetizationRecord).order_by(RtMonetizationRecord.created_at.desc(), RtMonetizationRecord.id.desc()).limit(100)).all()
    people_ids = {r.actor_user_id for r in records if r.actor_user_id} | {r.creator_user_id for r in records if r.creator_user_id}
    people = {u.id: u for u in db.scalars(select(User).where(User.id.in_(people_ids))).all()} if people_ids else {}
    payouts = db.scalars(select(RtCreatorPayoutRequest).where(RtCreatorPayoutRequest.status == "pending").order_by(RtCreatorPayoutRequest.created_at.asc()).limit(100)).all()
    payout_people = {u.id: u for u in db.scalars(select(User).where(User.id.in_({x.creator_user_id for x in payouts}))).all()} if payouts else {}
    return {
        "totals": {
            "premium_sales_usd": total(RtMonetizationRecord.gross_amount_usd, RtMonetizationRecord.record_type == "premium_sale"),
            "kilos_sales_usd": total(RtMonetizationRecord.gross_amount_usd, RtMonetizationRecord.record_type == "kilos_sale"),
            "kilos_pack_margin_usd": total(RtMonetizationRecord.platform_commission_usd, RtMonetizationRecord.record_type == "kilos_sale"),
            "gift_commission_usd": total(RtMonetizationRecord.platform_commission_usd, RtMonetizationRecord.record_type == "kilos_gift"),
            "ad_revenue_usd": total(RtMonetizationRecord.gross_amount_usd, RtMonetizationRecord.record_type == "ad_revenue"),
            "owner_ad_share_usd": total(RtMonetizationRecord.platform_commission_usd, RtMonetizationRecord.record_type == "ad_revenue"),
            "marketplace_gross_usd": total(RtMonetizationRecord.gross_amount_usd, RtMonetizationRecord.record_type == "marketplace_sale"),
            "marketplace_commission_usd": total(RtMonetizationRecord.platform_commission_usd, RtMonetizationRecord.record_type == "marketplace_sale"),
            "processing_fees_usd": total(RtMonetizationRecord.processing_fee_usd),
            "premium_processing_fees_usd": total(RtMonetizationRecord.processing_fee_usd, RtMonetizationRecord.record_type == "premium_sale"),
            "kilos_processing_fees_usd": total(RtMonetizationRecord.processing_fee_usd, RtMonetizationRecord.record_type == "kilos_sale"),
            "marketplace_processing_fees_usd": total(RtMonetizationRecord.processing_fee_usd, RtMonetizationRecord.record_type == "marketplace_sale"),
            "creator_earnings_usd": total(RtMonetizationRecord.creator_amount_usd),
            "premium_net_after_processing_usd": format(premium_gross - premium_fee, ".2f"),
            "kilos_margin_after_processing_usd": format(kilos_margin - kilos_fee, ".2f"),
            "estimated_owner_platform_revenue_usd": format(estimated_owner_net, ".2f"),
        },
        "records": [{"id": r.id, "type": r.record_type, "actor": people[r.actor_user_id].username if r.actor_user_id in people else "—", "creator": people[r.creator_user_id].username if r.creator_user_id in people else "—", "gross_usd": format(_money(r.gross_amount_usd), ".2f"), "processor_fee_usd": format(_money(r.processing_fee_usd), ".2f"), "platform_usd": format(_money(r.platform_commission_usd), ".2f"), "creator_usd": format(_money(r.creator_amount_usd), ".2f"), "reference": r.reference, "note": r.note, "created_at": _rt_iso(r.created_at)} for r in records],
        "pending_payouts": [{"id": p.id, "username": payout_people[p.creator_user_id].username if p.creator_user_id in payout_people else "deleted-account", "amount_usd": format(_money(p.amount_usd), ".2f"), "created_at": _rt_iso(p.created_at), "note": p.payout_note} for p in payouts],
        "payments_configured": bool(STRIPE_SECRET_KEY and STRIPE_WEBHOOK_SECRET),
    }


@app.post("/api/admin/monetization/ad-revenue", status_code=status.HTTP_201_CREATED)
def admin_record_ad_revenue(body: AdminAdRevenueBody, request: Request, db: Session = Depends(get_db)) -> dict:
    owner = require_owner(request, db)
    require_same_origin(request)
    creator = db.scalar(select(User).where(func.lower(User.username) == body.creator_username.strip().lstrip("@").lower()))
    if not creator:
        raise HTTPException(status_code=404, detail="Creator account not found.")
    gross = _money(body.amount_usd)
    creator_amount = _round_money(gross * AD_CREATOR_SHARE)
    owner_amount = _round_money(gross - creator_amount)
    wallet = _ensure_creator_wallet(db, creator.id, for_update=True)
    wallet.available_usd = _round_money(wallet.available_usd + creator_amount)
    _record_monetization(db, "ad_revenue", gross, Decimal("0.00"), owner_amount, creator_amount,
                         actor_user_id=owner.id, creator_user_id=creator.id, reference=body.reference,
                         note=(body.note.strip() + " | Traditional ad revenue split: creator 55%, InnerCly 45%.").strip(" |"))
    db.commit()
    return {"ok": True, "creator_usd": format(creator_amount, ".2f"), "owner_usd": format(owner_amount, ".2f"), "message": "Ad revenue recorded using the 55% creator / 45% InnerCly split."}


@app.post("/api/admin/monetization/marketplace-sale", status_code=status.HTTP_201_CREATED)
def admin_record_marketplace_sale(body: AdminMarketplaceSaleBody, request: Request, db: Session = Depends(get_db)) -> dict:
    owner = require_owner(request, db)
    require_same_origin(request)
    seller = db.scalar(select(User).where(func.lower(User.username) == body.seller_username.strip().lstrip("@").lower()))
    if not seller:
        raise HTTPException(status_code=404, detail="Seller account not found.")
    gross = _money(body.gross_amount_usd)
    fee = _money(body.processing_fee_usd)
    # Manual accounting accepts a category/type hint in the note to keep legacy forms backward compatible.
    requested_type = (body.note or "").lower()
    listing_type = "digital" if "digital" in requested_type else "physical"
    base_rate = DIGITAL_MARKETPLACE_COMMISSION_RATE if listing_type == "digital" else PHYSICAL_MARKETPLACE_COMMISSION_RATE
    exclusive_hub = (seller.username or "").lower() in EXCLUSIVE_SUBSCRIPTION_HUB_USERNAMES
    commission_rate = base_rate * Decimal("0.50") if exclusive_hub else base_rate
    commission = _round_money(gross * commission_rate)
    seller_amount = _round_money(gross - fee - commission)
    if fee >= gross or seller_amount < Decimal("0.00"):
        raise HTTPException(status_code=422, detail="The processor fee and applicable Marketplace commission must fit within the sale amount.")
    wallet = _ensure_creator_wallet(db, seller.id, for_update=True)
    wallet.available_usd = _round_money(wallet.available_usd + seller_amount)
    _record_monetization(db, "marketplace_sale", gross, fee, commission, seller_amount,
                         actor_user_id=owner.id, creator_user_id=seller.id, reference=body.reference,
                         note=(body.note.strip() + " | Seller receives gross less exact processor fee and 5% InnerCly commission.").strip(" |"))
    db.commit()
    return {"ok": True, "seller_usd": format(seller_amount, ".2f"), "processor_fee_usd": format(fee, ".2f"), "owner_usd": format(commission, ".2f"), "message": f"Marketplace sale recorded: actual processor fee passed through to the seller, plus {commission_rate * 100}% {listing_type} platform commission."}


@app.patch("/api/admin/monetization/payouts/{payout_id}")
def admin_review_creator_payout(payout_id: int, body: dict, request: Request, db: Session = Depends(get_db)) -> dict:
    owner = require_owner(request, db)
    require_same_origin(request)
    row = db.get(RtCreatorPayoutRequest, payout_id)
    if not row:
        raise HTTPException(status_code=404, detail="Payout request not found.")
    if row.status != "pending":
        raise HTTPException(status_code=409, detail="This payout request has already been reviewed.")
    decision = str(body.get("status", "")).strip().lower()
    note = str(body.get("note", "")).strip()[:500]
    if decision not in {"paid", "rejected"}:
        raise HTTPException(status_code=422, detail="Choose paid or rejected.")
    row.status = decision
    row.reviewed_by = owner.id
    row.payout_note = note
    row.updated_at = datetime.now(timezone.utc)
    if decision == "rejected":
        wallet = _ensure_creator_wallet(db, row.creator_user_id, for_update=True)
        wallet.available_usd = _round_money(wallet.available_usd + _money(row.amount_usd))
    else:
        _record_monetization(db, "creator_payout", _money(row.amount_usd), Decimal("0.00"), Decimal("0.00"), Decimal("0.00"),
                             actor_user_id=owner.id, creator_user_id=row.creator_user_id, reference=f"payout:{row.id}",
                             note="Owner marked payout as paid after external payment confirmation. " + note)
    db.commit()
    return {"ok": True, "message": "Payout marked paid. Record an actual external transfer before using this status." if decision == "paid" else "Payout rejected; reserved earnings were returned to the creator."}


# Minimal one-to-many WebRTC signaling. Media stays peer-to-peer; Render relays signaling only.
_LIVE_ROOMS: dict[int, dict[str, dict[str, object]]] = {}
_LIVE_ROOMS_LOCK = asyncio.Lock()

async def _live_send(ws: WebSocket, payload: dict) -> None:
    try:
        await ws.send_json(payload)
    except Exception:
        pass

async def _live_relay(stream_id: int, payload: dict, to_peer: str) -> None:
    async with _LIVE_ROOMS_LOCK:
        target = _LIVE_ROOMS.get(stream_id, {}).get(to_peer)
        peer_ws = target.get("ws") if target else None
    if peer_ws:
        await _live_send(peer_ws, payload)

@app.websocket("/ws/live/{stream_id}")
async def live_stream_signaling(websocket: WebSocket, stream_id: int):
    token = websocket.cookies.get(SESSION_COOKIE)
    db = SessionLocal()
    user = None
    live_row = None
    try:
        if token:
            now = datetime.now(timezone.utc)
            session_row = db.scalar(select(AuthSession).where(AuthSession.token_hash == token_fingerprint(token), AuthSession.expires_at > now))
            user = session_row.user if session_row else None
        live_row = db.get(RtLiveStream, stream_id)
        if not user or not live_row or live_row.status != "live":
            await websocket.close(code=4401 if not user else 4404)
            return
        user_id, username, host_id = user.id, user.username, live_row.host_id
    finally:
        db.close()
    await websocket.accept()
    peer_id = secrets.token_urlsafe(12)
    role = "host" if user_id == host_id else "viewer"
    entry = {"ws": websocket, "user_id": user_id, "username": username, "role": role, "peer_id": peer_id}
    async with _LIVE_ROOMS_LOCK:
        room = _LIVE_ROOMS.setdefault(stream_id, {})
        if role == "host" and any(x.get("role") == "host" for x in room.values()):
            await _live_send(websocket, {"type": "error", "message": "This live stream is already connected from another browser tab."})
            await websocket.close(code=4409)
            return
        room[peer_id] = entry
        host_peer = next((k for k, x in room.items() if x.get("role") == "host"), None)
        viewers = [{"peer_id": k, "username": str(x.get("username", "Viewer"))} for k, x in room.items() if x.get("role") == "viewer"]
    await _live_send(websocket, {"type": "ready", "role": role, "peer_id": peer_id, "host_peer": host_peer, "viewers": viewers})
    if role == "viewer" and host_peer:
        await _live_relay(stream_id, {"type": "viewer-joined", "peer_id": peer_id, "username": username}, host_peer)
    elif role == "host":
        for viewer in viewers:
            await _live_send(websocket, {"type": "viewer-joined", "peer_id": viewer["peer_id"], "username": viewer["username"]})
    try:
        while True:
            message = await websocket.receive_json()
            if not isinstance(message, dict):
                continue
            kind = str(message.get("type", ""))
            if kind not in {"offer", "answer", "ice"}:
                continue
            target_id = str(message.get("to", ""))
            if not target_id or target_id == peer_id:
                continue
            data = message.get("data")
            if kind == "offer" and role != "host":
                continue
            if kind == "answer" and role != "viewer":
                continue
            await _live_relay(stream_id, {"type": kind, "from": peer_id, "from_username": username, "data": data}, target_id)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        async with _LIVE_ROOMS_LOCK:
            room = _LIVE_ROOMS.get(stream_id, {})
            room.pop(peer_id, None)
            remaining_host = next((k for k, x in room.items() if x.get("role") == "host"), None)
            if not room:
                _LIVE_ROOMS.pop(stream_id, None)
        if role == "viewer" and remaining_host:
            await _live_relay(stream_id, {"type": "viewer-left", "peer_id": peer_id}, remaining_host)
        if role == "host":
            db2 = SessionLocal()
            try:
                row = db2.get(RtLiveStream, stream_id)
                if row and row.status == "live":
                    row.status = "ended"
                    row.ended_at = datetime.now(timezone.utc)
                    db2.commit()
            except Exception:
                db2.rollback()
            finally:
                db2.close()
            async with _LIVE_ROOMS_LOCK:
                others = list(_LIVE_ROOMS.get(stream_id, {}).values())
            for peer in others:
                await _live_send(peer["ws"], {"type": "stream-ended"})

@app.get("/api/profiles/{username}")
def rt_public_profile(username: str, request: Request, db: Session = Depends(get_db)) -> dict:
    viewer = require_rt_user(request, db)
    normalized = username.strip().lstrip("@").lower()
    target = db.scalar(select(User).where(func.lower(User.username) == normalized))
    if not target:
        raise HTTPException(status_code=404, detail="That InnerCly profile could not be found.")
    if target.id != viewer.id and _rt_is_blocked(db, viewer.id, target.id):
        raise HTTPException(status_code=404, detail="That InnerCly profile could not be found.")
    is_friend = _rt_are_friends(db, viewer.id, target.id)
    posts_query = select(RtPost).where(RtPost.author_id == target.id).order_by(RtPost.created_at.desc(), RtPost.id.desc()).limit(60)
    posts = [post for post in db.scalars(posts_query).all() if _rt_can_view_post(db, viewer.id, post)]
    followers = db.scalar(select(func.count(RtUserFollow.id)).where(RtUserFollow.following_id == target.id)) or 0
    following = db.scalar(select(func.count(RtUserFollow.id)).where(RtUserFollow.follower_id == target.id)) or 0
    friends_count = db.scalar(select(func.count(RtFriendship.id)).where(or_(RtFriendship.user_a_id == target.id, RtFriendship.user_b_id == target.id))) or 0
    is_following = db.scalar(select(RtUserFollow.id).where(RtUserFollow.follower_id == viewer.id, RtUserFollow.following_id == target.id)) is not None
    outgoing = db.scalar(select(RtFriendRequest.id).where(RtFriendRequest.sender_id == viewer.id, RtFriendRequest.receiver_id == target.id, RtFriendRequest.status == "pending")) is not None
    incoming = db.scalar(select(RtFriendRequest.id).where(RtFriendRequest.sender_id == target.id, RtFriendRequest.receiver_id == viewer.id, RtFriendRequest.status == "pending")) is not None
    return {"user": _rt_user(target), "posts": [_rt_post_json(db, post, viewer.id) for post in posts],
            "stats": {"posts": len(posts), "followers": followers, "following": following, "friends": friends_count},
            "is_self": target.id == viewer.id, "is_friend": is_friend, "is_following": is_following,
            "request_sent": outgoing, "request_received": incoming}


@app.get("/api/people")
def rt_people(request: Request, q: str = "", db: Session = Depends(get_db)) -> dict:
    user = require_rt_user(request, db)
    term = q.strip().lower()
    query = select(User).where(User.id != user.id)
    blocked_ids = set(db.scalars(select(RtUserBlock.blocked_id).where(RtUserBlock.blocker_id == user.id)).all())
    blocked_ids.update(db.scalars(select(RtUserBlock.blocker_id).where(RtUserBlock.blocked_id == user.id)).all())
    if blocked_ids:
        query = query.where(User.id.not_in(blocked_ids))
    if term:
        like = f"%{term[:48]}%"
        query = query.where(or_(func.lower(User.username).like(like), func.lower(User.display_name).like(like)))
    rows = db.scalars(query.order_by(User.display_name.asc()).limit(30)).all()
    outgoing = {x.receiver_id for x in db.scalars(select(RtFriendRequest).where(RtFriendRequest.sender_id == user.id, RtFriendRequest.status == "pending")).all()}
    incoming = {x.sender_id for x in db.scalars(select(RtFriendRequest).where(RtFriendRequest.receiver_id == user.id, RtFriendRequest.status == "pending")).all()}
    following_ids = set(db.scalars(select(RtUserFollow.following_id).where(RtUserFollow.follower_id == user.id)).all())
    follower_ids = set(db.scalars(select(RtUserFollow.follower_id).where(RtUserFollow.following_id == user.id)).all())
    result=[]
    for other in rows:
        is_friend = _rt_are_friends(db, user.id, other.id)
        followers_count = db.scalar(select(func.count(RtUserFollow.id)).where(RtUserFollow.following_id == other.id)) or 0
        following_count = db.scalar(select(func.count(RtUserFollow.id)).where(RtUserFollow.follower_id == other.id)) or 0
        result.append({**_rt_user(other), "is_friend": is_friend, "request_sent": other.id in outgoing,
                       "request_received": other.id in incoming, "is_following": other.id in following_ids,
                       "follows_you": other.id in follower_ids, "followers_count": followers_count,
                       "following_count": following_count})
    return {"items": result}

@app.get("/api/follows")
def rt_user_follows(request: Request, db: Session = Depends(get_db)) -> dict:
    user = require_rt_user(request, db)
    outgoing = db.scalars(select(RtUserFollow).where(RtUserFollow.follower_id == user.id).order_by(RtUserFollow.created_at.desc())).all()
    incoming = db.scalars(select(RtUserFollow).where(RtUserFollow.following_id == user.id).order_by(RtUserFollow.created_at.desc())).all()
    following = []
    followers = []
    for row in outgoing:
        person = db.get(User, row.following_id)
        if person:
            following.append({**_rt_user(person), "followed_at": _rt_iso(row.created_at)})
    for row in incoming:
        person = db.get(User, row.follower_id)
        if person:
            followers.append({**_rt_user(person), "followed_at": _rt_iso(row.created_at)})
    return {"following": following, "followers": followers,
            "following_count": len(following), "followers_count": len(followers)}

@app.post("/api/follows", status_code=status.HTTP_201_CREATED)
def rt_follow_user(body: dict, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    username = str(body.get("username", "")).strip().lstrip("@").lower()
    if not username:
        raise HTTPException(status_code=422, detail="Enter the username of the person to follow.")
    target = db.scalar(select(User).where(func.lower(User.username) == username))
    if not target:
        raise HTTPException(status_code=404, detail="No InnerCly account with that username was found.")
    if target.id == user.id:
        raise HTTPException(status_code=400, detail="You cannot follow your own account.")
    existing = db.scalar(select(RtUserFollow).where(RtUserFollow.follower_id == user.id, RtUserFollow.following_id == target.id))
    if not existing:
        db.add(RtUserFollow(follower_id=user.id, following_id=target.id))
        _rt_notify(db, target.id, f"{user.display_name} started following you", "follow", user.id)
        db.commit()
    return {"ok": True, "following": True, "username": target.username}

@app.delete("/api/follows/{username}")
def rt_unfollow_user(username: str, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request)
    user = require_rt_user(request, db)
    normalized = username.strip().lstrip("@").lower()
    target = db.scalar(select(User).where(func.lower(User.username) == normalized))
    if not target:
        raise HTTPException(status_code=404, detail="Person not found.")
    if target.id == user.id:
        raise HTTPException(status_code=400, detail="You cannot unfollow your own account.")
    row = db.scalar(select(RtUserFollow).where(RtUserFollow.follower_id == user.id, RtUserFollow.following_id == target.id))
    if row:
        db.delete(row)
        db.commit()
    return {"ok": True, "following": False, "username": target.username}

@app.get("/api/friends")
def rt_friends(request: Request, db: Session = Depends(get_db)) -> dict:
    user = require_rt_user(request, db)
    pairs = db.scalars(select(RtFriendship).where(or_(RtFriendship.user_a_id == user.id, RtFriendship.user_b_id == user.id))).all()
    friends=[]
    for pair in pairs:
        other_id = pair.user_b_id if pair.user_a_id == user.id else pair.user_a_id
        other = db.get(User, other_id)
        if other: friends.append(_rt_user(other))
    incoming=[]; outgoing=[]
    for row in db.scalars(select(RtFriendRequest).where(RtFriendRequest.status == "pending", or_(RtFriendRequest.sender_id == user.id, RtFriendRequest.receiver_id == user.id)).order_by(RtFriendRequest.created_at.desc())).all():
        other_id = row.sender_id if row.receiver_id == user.id else row.receiver_id
        other = db.get(User, other_id)
        item={"id":row.id, "created_at":_rt_iso(row.created_at), "user":_rt_user(other) if other else None}
        if row.receiver_id == user.id: incoming.append(item)
        else: outgoing.append(item)
    return {"friends": friends, "incoming": incoming, "outgoing": outgoing}

@app.post("/api/friend-requests", status_code=status.HTTP_201_CREATED)
def rt_send_friend_request(body: RtFriendRequestBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request); user = require_rt_user(request, db)
    target = db.scalar(select(User).where(User.username == body.username.strip().lower()))
    if not target: raise HTTPException(status_code=404, detail="No InnerCly account with that username was found.")
    if target.id == user.id: raise HTTPException(status_code=400, detail="You cannot send a friend request to yourself.")
    if _rt_are_friends(db, user.id, target.id): raise HTTPException(status_code=409, detail="You are already friends.")
    reverse = db.scalar(select(RtFriendRequest).where(RtFriendRequest.sender_id == target.id, RtFriendRequest.receiver_id == user.id, RtFriendRequest.status == "pending"))
    if reverse:
        lo, hi = _rt_pair(user.id, target.id); db.add(RtFriendship(user_a_id=lo,user_b_id=hi)); reverse.status="accepted"
        _rt_notify(db, target.id, f"{user.display_name} accepted your friend request", "friend", user.id); db.commit()
        return {"ok":True,"status":"accepted"}
    existing = db.scalar(select(RtFriendRequest).where(RtFriendRequest.sender_id == user.id, RtFriendRequest.receiver_id == target.id, RtFriendRequest.status == "pending"))
    if existing: raise HTTPException(status_code=409, detail="A friend request is already pending.")
    row=RtFriendRequest(sender_id=user.id,receiver_id=target.id,status="pending");db.add(row)
    _rt_notify(db,target.id,f"{user.display_name} sent you a friend request","friend_request",row.id);db.commit();db.refresh(row)
    return {"ok":True,"id":row.id,"status":"pending"}

@app.post("/api/friend-requests/{request_id}/respond")
def rt_respond_friend_request(request_id: int, body: dict, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request); user = require_rt_user(request, db)
    row=db.get(RtFriendRequest,request_id)
    if not row or row.receiver_id != user.id or row.status != "pending": raise HTTPException(status_code=404,detail="Pending friend request not found.")
    action=str(body.get("action","" )).lower()
    if action not in ("accept","decline"): raise HTTPException(status_code=422,detail="Choose accept or decline.")
    row.status="accepted" if action=="accept" else "declined"
    if action=="accept":
        lo,hi=_rt_pair(row.sender_id,row.receiver_id)
        if not db.scalar(select(RtFriendship.id).where(RtFriendship.user_a_id==lo,RtFriendship.user_b_id==hi)): db.add(RtFriendship(user_a_id=lo,user_b_id=hi))
        sender=db.get(User,row.sender_id); _rt_notify(db,row.sender_id,f"{user.display_name} accepted your friend request","friend",user.id)
    db.commit(); return {"ok":True,"status":row.status}

@app.delete("/api/friends/{username}")
def rt_remove_friend(username: str, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request); user=require_rt_user(request,db)
    other=db.scalar(select(User).where(User.username==username.lower()))
    if not other: raise HTTPException(status_code=404,detail="Person not found.")
    lo,hi=_rt_pair(user.id,other.id); row=db.scalar(select(RtFriendship).where(RtFriendship.user_a_id==lo,RtFriendship.user_b_id==hi))
    if row: db.delete(row); db.commit()
    return {"ok":True}

@app.get("/api/chats/{username}/messages")
def rt_get_dm(username: str, request: Request, db: Session = Depends(get_db), after_id: int = 0) -> dict:
    user=require_rt_user(request,db); other=db.scalar(select(User).where(User.username==username.lower()))
    if not other: raise HTTPException(status_code=404,detail="Person not found.")
    if not _rt_are_friends(db,user.id,other.id): raise HTTPException(status_code=403,detail="You must be friends to use private chat.")
    if _rt_is_blocked(db, user.id, other.id): raise HTTPException(status_code=403, detail="Private chat is unavailable because one of these accounts is blocked.")
    rows=db.scalars(select(RtDirectMessage).where(or_(and_(RtDirectMessage.sender_id==user.id,RtDirectMessage.recipient_id==other.id),and_(RtDirectMessage.sender_id==other.id,RtDirectMessage.recipient_id==user.id)),RtDirectMessage.id>after_id).order_by(RtDirectMessage.id.asc()).limit(200)).all()
    out=[]
    for m in rows:
        author=db.get(User,m.sender_id); reply=db.get(RtDirectMessage,m.reply_to_id) if m.reply_to_id else None
        out.append({"id":m.id,"text":m.text,"media_data":m.media_data,"reply_to_id":m.reply_to_id,"reply_to_text":reply.text[:240] if reply else None,"edited":m.edited_at is not None,"reactions":_rt_message_reactions(db,"dm",m.id,user.id),"created_at":_rt_iso(m.created_at),"author":_rt_user(author) if author else None,"mine":m.sender_id==user.id})
    return {"items":out}

@app.post("/api/chats/{username}/messages", status_code=status.HTTP_201_CREATED)
def rt_send_dm(username: str, body: RtMessageBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request); user=require_rt_user(request,db); other=db.scalar(select(User).where(User.username==username.lower()))
    if not other: raise HTTPException(status_code=404,detail="Person not found.")
    if not _rt_are_friends(db,user.id,other.id): raise HTTPException(status_code=403,detail="You must be friends to use private chat.")
    if _rt_is_blocked(db, user.id, other.id): raise HTTPException(status_code=403, detail="Private chat is unavailable because one of these accounts is blocked.")
    text=body.text.strip(); media=_rt_check_media(body.media_data,images_only=False,max_chars=1_500_000)
    if not text and not media: raise HTTPException(status_code=422,detail="Write a message or attach media first.")
    reply_to_id=None
    if body.reply_to_id is not None:
        parent=db.get(RtDirectMessage,body.reply_to_id)
        if not parent or {parent.sender_id,parent.recipient_id}!={user.id,other.id}:
            raise HTTPException(status_code=404, detail="The message you are replying to was not found in this chat.")
        reply_to_id=parent.id
    row=RtDirectMessage(sender_id=user.id,recipient_id=other.id,text=text,media_data=media,reply_to_id=reply_to_id);db.add(row);_rt_notify(db,other.id,f"New message from {user.display_name}","chat",user.id);db.commit();db.refresh(row)
    return {"item":{"id":row.id,"text":row.text,"media_data":row.media_data,"reply_to_id":row.reply_to_id,"edited":False,"reactions":[],"created_at":_rt_iso(row.created_at),"author":_rt_user(user),"mine":True}}

@app.get("/api/groups")
def rt_list_groups(request: Request, db: Session = Depends(get_db)) -> dict:
    user=require_rt_user(request,db)
    rows=db.scalars(select(RtGroup).where(or_(RtGroup.visibility=="Public",RtGroup.owner_id==user.id, RtGroup.id.in_(select(RtGroupMember.group_id).where(RtGroupMember.user_id==user.id)))).order_by(RtGroup.created_at.desc()).limit(100)).all()
    return {"items":[_rt_group_json(db,g,user) for g in rows]}

@app.post("/api/groups", status_code=status.HTTP_201_CREATED)
def rt_create_group(body: RtGroupBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db)
    name=body.name.strip(); visibility=body.visibility.title()
    if visibility not in ("Public","Private"): raise HTTPException(status_code=422,detail="Choose Public or Private visibility.")
    existing=db.scalars(select(RtGroup).where(func.lower(RtGroup.name)==name.lower())).first()
    if existing: raise HTTPException(status_code=409,detail="A group with that name already exists.")
    group=RtGroup(owner_id=user.id,name=name,description=body.description.strip(),visibility=visibility);db.add(group);db.flush()
    db.add(RtGroupMember(group_id=group.id,user_id=user.id,role="owner"));db.commit();db.refresh(group)
    return {"item":_rt_group_json(db,group,user)}

@app.post("/api/groups/{group_id}/membership")
def rt_group_membership(group_id: int, body: dict, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);group=db.get(RtGroup,group_id)
    if not group: raise HTTPException(status_code=404,detail="Group not found.")
    action=str(body.get("action","join")).lower(); member=db.scalar(select(RtGroupMember).where(RtGroupMember.group_id==group_id,RtGroupMember.user_id==user.id))
    if action=="join":
        if group.visibility=="Private" and not member: raise HTTPException(status_code=403,detail="This group is private.")
        if not member: db.add(RtGroupMember(group_id=group_id,user_id=user.id,role="member")); _rt_notify(db,group.owner_id,f"{user.display_name} joined {group.name}","group",group.id); db.commit()
    elif action=="leave":
        if group.owner_id==user.id: raise HTTPException(status_code=400,detail="The group owner cannot leave. Delete the group instead.")
        if member: db.delete(member);db.commit()
    elif action=="delete":
        if group.owner_id!=user.id: raise HTTPException(status_code=403,detail="Only the group owner can delete it.")
        db.delete(group);db.commit();return {"ok":True,"deleted":True}
    else: raise HTTPException(status_code=422,detail="Choose join, leave, or delete.")
    return {"item":_rt_group_json(db,group,user)}

@app.get("/api/groups/{group_id}/messages")
def rt_get_group_messages(group_id: int, request: Request, db: Session = Depends(get_db), after_id: int = 0) -> dict:
    user=require_rt_user(request,db);group=db.get(RtGroup,group_id)
    if not group: raise HTTPException(status_code=404,detail="Group not found.")
    member=db.scalar(select(RtGroupMember.id).where(RtGroupMember.group_id==group_id,RtGroupMember.user_id==user.id))
    if not member: raise HTTPException(status_code=403,detail="Join this group to view its chat.")
    rows=db.scalars(select(RtGroupMessage).where(RtGroupMessage.group_id==group_id,RtGroupMessage.id>after_id).order_by(RtGroupMessage.id.asc()).limit(200)).all()
    out=[]
    for m in rows:
        reply=db.get(RtGroupMessage,m.reply_to_id) if m.reply_to_id else None
        out.append({"id":m.id,"text":m.text,"attachment_data":m.attachment_data,"reply_to_id":m.reply_to_id,"reply_to_text":reply.text[:240] if reply else None,"edited":m.edited_at is not None,"reactions":_rt_message_reactions(db,"group",m.id,user.id),"created_at":_rt_iso(m.created_at),"author":_rt_user(db.get(User,m.author_id)),"mine":m.author_id==user.id})
    return {"items":out}

@app.post("/api/groups/{group_id}/messages", status_code=status.HTTP_201_CREATED)
def rt_send_group_message(group_id: int, body: RtGroupMessageBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);group=db.get(RtGroup,group_id)
    if not group: raise HTTPException(status_code=404,detail="Group not found.")
    member=db.scalar(select(RtGroupMember.id).where(RtGroupMember.group_id==group_id,RtGroupMember.user_id==user.id))
    if not member: raise HTTPException(status_code=403,detail="Join this group before chatting.")
    text=body.text.strip();media=_rt_check_media(body.attachment_data,images_only=False,max_chars=1_500_000)
    if not text and not media: raise HTTPException(status_code=422,detail="Write a message or attach media.")
    reply_to_id=None
    if body.reply_to_id is not None:
        parent=db.get(RtGroupMessage,body.reply_to_id)
        if not parent or parent.group_id != group_id:
            raise HTTPException(status_code=404, detail="The message you are replying to was not found in this group.")
        reply_to_id=parent.id
    row=RtGroupMessage(group_id=group_id,author_id=user.id,text=text,attachment_data=media,reply_to_id=reply_to_id);db.add(row);db.commit();db.refresh(row)
    for memberrow in db.scalars(select(RtGroupMember).where(RtGroupMember.group_id==group_id,RtGroupMember.user_id!=user.id)).all(): _rt_notify(db,memberrow.user_id,f"New message in {group.name}","group",group.id)
    db.commit()
    return {"item":{"id":row.id,"text":row.text,"attachment_data":row.attachment_data,"reply_to_id":row.reply_to_id,"edited":False,"reactions":[],"created_at":_rt_iso(row.created_at),"author":_rt_user(user),"mine":True}}


# Authenticated in-process WebSocket signaling for real-time group voice/video calls.
_GROUP_CALL_ROOMS: dict[int, dict[WebSocket, dict[str, object]]] = {}
_GROUP_CALL_LOCK = asyncio.Lock()

async def _group_call_send(ws: WebSocket, payload: dict) -> None:
    try:
        await ws.send_json(payload)
    except Exception:
        pass

async def _group_call_broadcast(group_id: int, payload: dict, exclude: Optional[WebSocket] = None) -> None:
    async with _GROUP_CALL_LOCK:
        peers = list(_GROUP_CALL_ROOMS.get(group_id, {}).items())
    for peer_ws, _peer in peers:
        if peer_ws is not exclude:
            await _group_call_send(peer_ws, payload)

@app.websocket("/ws/group-calls/{group_id}")
async def rt_group_call_signaling(websocket: WebSocket, group_id: int):
    # Authenticate from the same secure session cookie used by the REST API.
    token = websocket.cookies.get(SESSION_COOKIE)
    db = SessionLocal()
    user = None
    try:
        if token:
            now = datetime.now(timezone.utc)
            session_row = db.scalar(select(AuthSession).where(AuthSession.token_hash == token_fingerprint(token), AuthSession.expires_at > now))
            user = session_row.user if session_row else None
        group = db.get(RtGroup, group_id)
        is_member = bool(user and group and db.scalar(select(RtGroupMember.id).where(RtGroupMember.group_id == group_id, RtGroupMember.user_id == user.id)))
        if not user or not group:
            await websocket.close(code=4401 if not user else 4404)
            return
        if not is_member:
            await websocket.close(code=4403)
            return
        username = user.username
        user_id = user.id
    finally:
        db.close()
    await websocket.accept()
    async with _GROUP_CALL_LOCK:
        room = _GROUP_CALL_ROOMS.setdefault(group_id, {})
        participants = [{'username': info['username']} for peer, info in room.items() if peer.client_state.name == 'CONNECTED' and info.get('username') != username]
        room[websocket] = {'username': username, 'user_id': user_id}
    await _group_call_send(websocket, {'type': 'ready', 'participants': participants})
    await _group_call_broadcast(group_id, {'type': 'peer-joined', 'from': username}, exclude=websocket)
    try:
        while True:
            message = await websocket.receive_json()
            if not isinstance(message, dict):
                continue
            kind = str(message.get('type', ''))
            if kind not in {'call-start', 'call-accept', 'call-decline', 'call-end', 'offer', 'answer', 'ice'}:
                continue
            payload = {'type': kind, 'from': username}
            if kind == 'call-start':
                payload['mode'] = 'video' if message.get('mode') == 'video' else 'audio'
            if kind in {'offer', 'answer', 'ice'}:
                target = str(message.get('to', ''))
                if not target or target == username:
                    continue
                payload['to'] = target
                payload['data'] = message.get('data')
                async with _GROUP_CALL_LOCK:
                    recipients = [(peer, info) for peer, info in _GROUP_CALL_ROOMS.get(group_id, {}).items() if info.get('username') == target]
                for peer, _info in recipients:
                    await _group_call_send(peer, payload)
            elif kind in {'call-accept', 'call-decline'}:
                target = str(message.get('to', ''))
                if target:
                    payload['to'] = target
                    async with _GROUP_CALL_LOCK:
                        recipients = [(peer, info) for peer, info in _GROUP_CALL_ROOMS.get(group_id, {}).items() if info.get('username') == target]
                    for peer, _info in recipients:
                        await _group_call_send(peer, payload)
                else:
                    await _group_call_broadcast(group_id, payload, exclude=websocket)
            else:
                await _group_call_broadcast(group_id, payload, exclude=websocket)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        async with _GROUP_CALL_LOCK:
            room = _GROUP_CALL_ROOMS.get(group_id, {})
            room.pop(websocket, None)
            if not room:
                _GROUP_CALL_ROOMS.pop(group_id, None)
        await _group_call_broadcast(group_id, {'type': 'call-end', 'from': username}, exclude=websocket)

@app.post("/api/marketplace/listings/{listing_id}/checkout")
def marketplace_listing_checkout(listing_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    """Start a USD card checkout; the exact Stripe fee and 5% commission are applied after payment confirmation."""
    require_same_origin(request)
    buyer = require_rt_user(request, db)
    listing = db.scalar(select(RtListing).where(RtListing.id == listing_id).with_for_update())
    if not listing or listing.status != "For sale":
        raise HTTPException(status_code=404, detail="This listing is no longer available for purchase.")
    if listing.seller_id == buyer.id:
        raise HTTPException(status_code=400, detail="You cannot purchase your own listing.")
    if listing.price_amount is None or (listing.currency_code or "").upper() != "USD":
        raise HTTPException(status_code=422, detail="Secure card checkout currently supports listings priced in USD. Use Message seller or Request delivery for other currencies.")
    amount = _round_money(listing.price_amount)
    if amount < Decimal("1.00"):
        raise HTTPException(status_code=422, detail="USD Marketplace card checkout requires a listing price of at least $1.00 so processing costs and the 5% commission can be covered.")
    pending = db.scalar(select(RtCheckoutPayment.id).where(
        RtCheckoutPayment.listing_id == listing.id,
        RtCheckoutPayment.status == "pending",
    ).limit(1))
    if pending:
        raise HTTPException(status_code=409, detail="Someone has already started checkout for this listing. Refresh the Marketplace and try again shortly.")
    seller = db.get(User, listing.seller_id)
    if not seller:
        raise HTTPException(status_code=404, detail="The seller account is no longer available.")
    # This pending payment record prevents a second buyer from starting checkout at the same time.
    db.flush()
    return _create_checkout(db, request, buyer, "marketplace", f"listing_{listing.id}", amount,
                            f"InnerCly Marketplace — {listing.title[:100]}", currency_code="USD",
                            listing_id=listing.id, seller_user_id=seller.id)


@app.get("/api/marketplace/currencies")
def rt_marketplace_currencies() -> dict:
    """Return supported active currency choices and region defaults for local price entry."""
    return {"items": CURRENCIES, "default_by_region": DEFAULT_BY_REGION}


@app.get("/api/marketplace/listings")
def rt_list_listings(request: Request, db: Session = Depends(get_db)) -> dict:
    user=require_rt_user(request,db)
    blocked_ids = set(db.scalars(select(RtUserBlock.blocked_id).where(RtUserBlock.blocker_id == user.id)).all())
    blocked_ids.update(db.scalars(select(RtUserBlock.blocker_id).where(RtUserBlock.blocked_id == user.id)).all())
    query=select(RtListing).where(RtListing.status.in_(["For sale","Reserved"]))
    if blocked_ids: query=query.where(RtListing.seller_id.not_in(blocked_ids))
    rows=db.scalars(query.order_by(RtListing.created_at.desc()).limit(100)).all()
    return {"items":[_rt_listing_json(db,x,user) for x in rows]}

@app.post("/api/marketplace/listings", status_code=status.HTTP_201_CREATED)
def rt_create_listing(body: RtListingBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db)
    image=_rt_check_media(body.image_data,images_only=True,max_chars=1_500_000)
    currency_code = (body.currency_code or "").strip().upper() or None
    price_amount = body.price_amount
    legacy_price = body.price.strip()
    if price_amount is not None:
        supported = {x["code"]: x for x in CURRENCIES}
        if not currency_code or currency_code not in supported:
            raise HTTPException(status_code=422, detail="Choose a supported international currency.")
        if price_amount <= 0:
            raise HTTPException(status_code=422, detail="Price must be greater than zero.")
        minor_units = int(supported[currency_code]["minor_units"])
        exponent = max(0, -price_amount.as_tuple().exponent)
        if exponent > minor_units:
            raise HTTPException(status_code=422, detail=f"{currency_code} supports up to {minor_units} decimal place(s).")
        legacy_price = f"{format(price_amount, 'f')} {currency_code}"
    else:
        # Older clients may still send free-text prices. Keep them intact for compatibility.
        if not legacy_price:
            raise HTTPException(status_code=422, detail="Enter a price amount and choose a currency.")
        currency_code = None
    category = body.category.strip().title()
    if category not in {"General", "Electronics", "Fashion", "Home", "Vehicles", "Books", "Services", "Beauty", "Sports", "Food", "Other"}:
        category = "General"
    listing_type = body.listing_type.strip().lower()
    row=RtListing(seller_id=user.id,title=body.title.strip(),category=category,listing_type=listing_type,price=legacy_price[:80],price_amount=price_amount,
                  currency_code=currency_code,description=body.description.strip(),image_data=image,status="For sale")
    db.add(row);db.commit();db.refresh(row);return {"item":_rt_listing_json(db,row,user)}

@app.delete("/api/marketplace/listings/{listing_id}")
def rt_delete_listing(listing_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);row=db.get(RtListing,listing_id)
    if not row: raise HTTPException(status_code=404,detail="Listing not found.")
    if row.seller_id!=user.id: raise HTTPException(status_code=403,detail="Only the seller can remove this listing.")
    row.status="Removed";db.commit();return {"ok":True}

@app.post("/api/marketplace/listings/{listing_id}/conversations", status_code=status.HTTP_201_CREATED)
def rt_market_conversation(listing_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);listing=db.get(RtListing,listing_id)
    if not listing or listing.status not in ("For sale","Reserved"): raise HTTPException(status_code=404,detail="Listing is no longer available.")
    if listing.seller_id==user.id: raise HTTPException(status_code=400,detail="You are the seller. Open your seller inbox instead.")
    if _rt_is_blocked(db,user.id,listing.seller_id): raise HTTPException(status_code=403,detail="Marketplace messages are unavailable because one of these accounts is blocked.")
    conv=db.scalar(select(RtMarketConversation).where(RtMarketConversation.listing_id==listing_id,RtMarketConversation.buyer_id==user.id))
    if not conv: conv=RtMarketConversation(listing_id=listing_id,buyer_id=user.id,seller_id=listing.seller_id);db.add(conv);db.commit();db.refresh(conv)
    seller=db.get(User,listing.seller_id)
    return {"item":{"id":conv.id,"listing_id":listing_id,"listing_title":listing.title,"buyer":_rt_user(user),"seller":_rt_user(seller),"is_seller":False}}

@app.get("/api/marketplace/conversations")
def rt_market_conversations(request: Request, db: Session = Depends(get_db)) -> dict:
    user=require_rt_user(request,db);rows=db.scalars(select(RtMarketConversation).where(or_(RtMarketConversation.buyer_id==user.id,RtMarketConversation.seller_id==user.id)).order_by(RtMarketConversation.created_at.desc()).limit(100)).all();out=[]
    for c in rows:
        listing=db.get(RtListing,c.listing_id);buyer=db.get(User,c.buyer_id);seller=db.get(User,c.seller_id)
        out.append({"id":c.id,"listing_id":c.listing_id,"listing_title":listing.title if listing else "Removed listing","buyer":_rt_user(buyer) if buyer else None,"seller":_rt_user(seller) if seller else None,"is_seller":c.seller_id==user.id})
    return {"items":out}

@app.get("/api/marketplace/conversations/{conversation_id}/messages")
def rt_get_market_messages(conversation_id: int, request: Request, db: Session = Depends(get_db), after_id: int = 0) -> dict:
    user=require_rt_user(request,db);conv=db.get(RtMarketConversation,conversation_id)
    if not conv or user.id not in (conv.buyer_id,conv.seller_id): raise HTTPException(status_code=404,detail="Conversation not found.")
    if _rt_is_blocked(db,user.id,conv.seller_id if user.id==conv.buyer_id else conv.buyer_id): raise HTTPException(status_code=403,detail="Marketplace messages are unavailable because one of these accounts is blocked.")
    rows=db.scalars(select(RtMarketMessage).where(RtMarketMessage.conversation_id==conversation_id,RtMarketMessage.id>after_id).order_by(RtMarketMessage.id.asc()).limit(200)).all()
    return {"items":[{"id":m.id,"text":m.text,"created_at":_rt_iso(m.created_at),"author":_rt_user(db.get(User,m.sender_id)),"mine":m.sender_id==user.id} for m in rows]}

@app.post("/api/marketplace/conversations/{conversation_id}/messages", status_code=status.HTTP_201_CREATED)
def rt_send_market_message(conversation_id: int, body: RtCommentBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);conv=db.get(RtMarketConversation,conversation_id)
    if not conv or user.id not in (conv.buyer_id,conv.seller_id): raise HTTPException(status_code=404,detail="Conversation not found.")
    if _rt_is_blocked(db,user.id,conv.seller_id if user.id==conv.buyer_id else conv.buyer_id): raise HTTPException(status_code=403,detail="Marketplace messages are unavailable because one of these accounts is blocked.")
    text=body.text.strip();row=RtMarketMessage(conversation_id=conversation_id,sender_id=user.id,text=text);db.add(row)
    other=conv.buyer_id if conv.seller_id==user.id else conv.seller_id;_rt_notify(db,other,f"Marketplace message from {user.display_name}","market_conversation",conversation_id)
    db.commit();db.refresh(row);return {"item":{"id":row.id,"text":row.text,"created_at":_rt_iso(row.created_at),"author":_rt_user(user),"mine":True}}

@app.get("/api/marketplace/deliveries")
def rt_list_deliveries(request: Request, db: Session = Depends(get_db)) -> dict:
    user=require_rt_user(request,db);rows=db.scalars(select(RtDelivery).where(or_(RtDelivery.buyer_id==user.id,RtDelivery.seller_id==user.id)).order_by(RtDelivery.created_at.desc()).limit(100)).all()
    return {"items":[_rt_delivery_json(db,x,user) for x in rows]}

@app.post("/api/marketplace/listings/{listing_id}/deliveries", status_code=status.HTTP_201_CREATED)
def rt_create_delivery(listing_id: int, body: RtDeliveryBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);listing=db.get(RtListing,listing_id)
    if not listing or listing.status!="For sale": raise HTTPException(status_code=404,detail="This listing is not available for purchase.")
    if listing.seller_id==user.id: raise HTTPException(status_code=400,detail="You cannot request delivery for your own listing.")
    row=RtDelivery(listing_id=listing.id,buyer_id=user.id,seller_id=listing.seller_id,phone=body.phone.strip(),address=body.address.strip(),note=body.note.strip(),status="Requested");db.add(row);_rt_notify(db,listing.seller_id,f"{user.display_name} requested delivery for {listing.title}","delivery",row.id);db.commit();db.refresh(row)
    return {"item":_rt_delivery_json(db,row,user)}

@app.patch("/api/marketplace/deliveries/{delivery_id}")
def rt_update_delivery(delivery_id: int, body: RtDeliveryStatusBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);row=db.get(RtDelivery,delivery_id)
    if not row: raise HTTPException(status_code=404,detail="Delivery request not found.")
    if row.seller_id!=user.id: raise HTTPException(status_code=403,detail="Only the seller can update delivery progress.")
    allowed={"Accepted","Declined","Preparing","Out for delivery","Delivered"}
    if body.status not in allowed: raise HTTPException(status_code=422,detail="Invalid delivery status.")
    transitions={"Requested":{"Accepted","Declined"},"Accepted":{"Preparing","Declined"},"Preparing":{"Out for delivery"},"Out for delivery":{"Delivered"},"Delivered":set(),"Declined":set()}
    if body.status not in transitions.get(row.status,set()): raise HTTPException(status_code=409,detail=f"Cannot move a request from {row.status} to {body.status}.")
    row.status=body.status;row.updated_at=datetime.now(timezone.utc);_rt_notify(db,row.buyer_id,f"Delivery status updated to {row.status}","delivery",row.id);db.commit();db.refresh(row)
    return {"item":_rt_delivery_json(db,row,user)}

@app.get("/api/marketplace/deliveries/{delivery_id}/messages")
def rt_get_delivery_messages(delivery_id: int, request: Request, db: Session = Depends(get_db), after_id: int = 0) -> dict:
    user=require_rt_user(request,db);delivery=db.get(RtDelivery,delivery_id)
    if not delivery or user.id not in (delivery.buyer_id,delivery.seller_id): raise HTTPException(status_code=404,detail="Delivery chat not found.")
    rows=db.scalars(select(RtDeliveryMessage).where(RtDeliveryMessage.delivery_id==delivery_id,RtDeliveryMessage.id>after_id).order_by(RtDeliveryMessage.id.asc()).limit(200)).all()
    return {"items":[{"id":m.id,"text":m.text,"created_at":_rt_iso(m.created_at),"author":_rt_user(db.get(User,m.sender_id)),"mine":m.sender_id==user.id} for m in rows]}

@app.post("/api/marketplace/deliveries/{delivery_id}/messages", status_code=status.HTTP_201_CREATED)
def rt_send_delivery_message(delivery_id: int, body: RtCommentBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);delivery=db.get(RtDelivery,delivery_id)
    if not delivery or user.id not in (delivery.buyer_id,delivery.seller_id): raise HTTPException(status_code=404,detail="Delivery chat not found.")
    row=RtDeliveryMessage(delivery_id=delivery_id,sender_id=user.id,text=body.text.strip());db.add(row);other=delivery.buyer_id if user.id==delivery.seller_id else delivery.seller_id;_rt_notify(db,other,f"Delivery message from {user.display_name}","delivery",delivery.id);db.commit();db.refresh(row)
    return {"item":{"id":row.id,"text":row.text,"created_at":_rt_iso(row.created_at),"author":_rt_user(user),"mine":True}}

@app.get("/api/community/{kind}")
def rt_list_community(kind: str, request: Request, db: Session = Depends(get_db)) -> dict:
    user=require_rt_user(request,db)
    if kind not in ("pages","events"): raise HTTPException(status_code=404,detail="Unknown community section.")
    rec_kind=kind[:-1]
    rows=db.scalars(select(RtCommunityRecord).where(RtCommunityRecord.kind==rec_kind).order_by(RtCommunityRecord.created_at.desc()).limit(100)).all();items=[]
    for r in rows:
        owner=db.get(User,r.owner_id);followers=db.scalar(select(func.count(RtCommunityFollow.id)).where(RtCommunityFollow.record_id==r.id)) or 0
        joined=db.scalar(select(RtCommunityFollow.id).where(RtCommunityFollow.record_id==r.id,RtCommunityFollow.user_id==user.id)) is not None
        items.append({"id":r.id,"kind":r.kind,"title":r.title,"body":r.body,"extra":__import__("json").loads(r.extra_json or "{}"),"created_at":_rt_iso(r.created_at),"owner":_rt_user(owner) if owner else None,"followers":followers,"joined":joined,"is_owner":r.owner_id==user.id})
    return {"items":items}

@app.post("/api/community/{kind}", status_code=status.HTTP_201_CREATED)
def rt_create_community(kind: str, body: RtCommunityBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db)
    if kind not in ("pages","events"): raise HTTPException(status_code=404,detail="Unknown community section.")
    title=body.title.strip();row=RtCommunityRecord(kind=kind[:-1],owner_id=user.id,title=title,body=body.body.strip(),extra_json=__import__("json").dumps(body.extra))
    db.add(row);db.commit();db.refresh(row)
    return {"item":{"id":row.id,"kind":row.kind,"title":row.title,"body":row.body,"extra":body.extra,"created_at":_rt_iso(row.created_at),"owner":_rt_user(user),"followers":0,"joined":False,"is_owner":True}}

@app.post("/api/community/{kind}/{record_id}/follow")
def rt_follow_community(kind: str, record_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db)
    if kind not in ("pages","events"): raise HTTPException(status_code=404,detail="Unknown community section.")
    row=db.get(RtCommunityRecord,record_id)
    if not row or row.kind!=kind[:-1]: raise HTTPException(status_code=404,detail="Item not found.")
    follow=db.scalar(select(RtCommunityFollow).where(RtCommunityFollow.record_id==row.id,RtCommunityFollow.user_id==user.id))
    if follow: db.delete(follow);joined=False
    else: db.add(RtCommunityFollow(record_id=row.id,user_id=user.id));joined=True
    db.commit();count=db.scalar(select(func.count(RtCommunityFollow.id)).where(RtCommunityFollow.record_id==row.id)) or 0
    return {"joined":joined,"count":count}

@app.delete("/api/community/{kind}/{record_id}")
def rt_delete_community(kind: str, record_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db)
    if kind not in ("pages","events"): raise HTTPException(status_code=404,detail="Unknown community section.")
    row=db.get(RtCommunityRecord,record_id)
    if not row or row.kind!=kind[:-1]: raise HTTPException(status_code=404,detail="Item not found.")
    if row.owner_id!=user.id: raise HTTPException(status_code=403,detail="Only the creator can delete this item.")
    db.delete(row);db.commit();return {"ok":True}

@app.get("/api/saved")
def rt_get_saved(request: Request, db: Session = Depends(get_db)) -> dict:
    user=require_rt_user(request,db);rows=db.scalars(select(RtSavedItem).where(RtSavedItem.user_id==user.id).order_by(RtSavedItem.created_at.desc())).all();out=[]
    for r in rows:
        resource=None
        if r.resource_type=="post":
            resource=db.get(RtPost,r.resource_id)
            if resource and _rt_can_view_post(db,user.id,resource): resource=_rt_post_json(db,resource,user.id)
            else: resource=None
        elif r.resource_type=="listing":
            resource=db.get(RtListing,r.resource_id)
            if resource: resource=_rt_listing_json(db,resource,user)
        if resource: out.append({"id":r.id,"resource_type":r.resource_type,"resource_id":r.resource_id,"collection_name":getattr(r,"collection_name","Saved") or "Saved","created_at":_rt_iso(r.created_at),"item":resource})
    return {"items":out}

@app.post("/api/saved", status_code=status.HTTP_201_CREATED)
def rt_save_item(body: RtSavedBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db)
    if body.resource_type=="post": obj=db.get(RtPost,body.resource_id)
    else: obj=db.get(RtListing,body.resource_id)
    if not obj or (body.resource_type=="post" and not _rt_can_view_post(db,user.id,obj)): raise HTTPException(status_code=404,detail="Item not found.")
    existing=db.scalar(select(RtSavedItem).where(RtSavedItem.user_id==user.id,RtSavedItem.resource_type==body.resource_type,RtSavedItem.resource_id==body.resource_id))
    collection = body.collection_name.strip() or "Saved"
    if not existing: db.add(RtSavedItem(user_id=user.id,resource_type=body.resource_type,resource_id=body.resource_id,collection_name=collection));db.commit()
    elif (getattr(existing,"collection_name","Saved") or "Saved") != collection:
        existing.collection_name=collection;db.commit()
    return {"ok":True,"collection_name":collection}

@app.patch("/api/saved/{saved_id}")
def rt_move_saved_item(saved_id: int, body: RtSavedCollectionBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);row=db.get(RtSavedItem,saved_id)
    if not row or row.user_id!=user.id: raise HTTPException(status_code=404,detail="Saved item not found.")
    row.collection_name=body.collection_name.strip() or "Saved";db.commit();return {"ok":True,"collection_name":row.collection_name}

@app.delete("/api/saved/{saved_id}")
def rt_unsave_item(saved_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);row=db.get(RtSavedItem,saved_id)
    if not row or row.user_id!=user.id: raise HTTPException(status_code=404,detail="Saved item not found.")
    db.delete(row);db.commit();return {"ok":True}

@app.get("/api/notifications")
def rt_get_notifications(request: Request, db: Session = Depends(get_db)) -> dict:
    user=require_rt_user(request,db);rows=db.scalars(select(RtNotification).where(RtNotification.user_id==user.id).order_by(RtNotification.created_at.desc()).limit(100)).all()
    return {"items":[{"id":n.id,"text":n.text,"link_type":n.link_type,"link_id":n.link_id,"is_read":n.is_read,"created_at":_rt_iso(n.created_at)} for n in rows]}

@app.post("/api/notifications/{notification_id}/read")
def rt_read_notification(notification_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);row=db.get(RtNotification,notification_id)
    if not row or row.user_id!=user.id: raise HTTPException(status_code=404,detail="Notification not found.")
    row.is_read=True;db.commit();return {"ok":True}

@app.post("/api/notifications/read-all")
def rt_read_notifications(request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db)
    rows=db.scalars(select(RtNotification).where(RtNotification.user_id==user.id,RtNotification.is_read==False)).all()
    for row in rows: row.is_read=True
    db.commit();return {"ok":True,"count":len(rows)}

@app.get("/api/safety")
def rt_safety_summary(request: Request, db: Session = Depends(get_db)) -> dict:
    user=require_rt_user(request,db)
    rows=db.scalars(select(RtUserBlock).where(RtUserBlock.blocker_id==user.id).order_by(RtUserBlock.created_at.desc())).all()
    items=[]
    for row in rows:
        target=db.get(User,row.blocked_id)
        if target: items.append({"id":row.id,"username":target.username,"display_name":target.display_name,"badges":active_account_badges(target),"created_at":_rt_iso(row.created_at)})
    muted_rows=db.scalars(select(RtUserMute).where(RtUserMute.muter_id==user.id).order_by(RtUserMute.created_at.desc())).all()
    muted=[]
    for row in muted_rows:
        target=db.get(User,row.muted_id)
        if target: muted.append({"id":row.id,"username":target.username,"display_name":target.display_name,"badges":active_account_badges(target),"created_at":_rt_iso(row.created_at)})
    return {"blocked":items,"muted":muted,"privacy":{"stories":"friends-only","private_chat":"friends-only","posts":"public-or-friends-only-per-post"}}

@app.post("/api/blocks", status_code=status.HTTP_201_CREATED)
def rt_block_user(body: RtBlockBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db)
    username=body.username.strip().lstrip("@").lower()
    target=db.scalar(select(User).where(func.lower(User.username)==username))
    if not target: raise HTTPException(status_code=404,detail="That account could not be found.")
    if target.id==user.id: raise HTTPException(status_code=400,detail="You cannot block your own account.")
    existing=db.scalar(select(RtUserBlock).where(RtUserBlock.blocker_id==user.id,RtUserBlock.blocked_id==target.id))
    if not existing: db.add(RtUserBlock(blocker_id=user.id,blocked_id=target.id));db.commit()
    # Remove follows and friendships both ways so blocked communication stops consistently.
    for follow in db.scalars(select(RtUserFollow).where(or_(and_(RtUserFollow.follower_id==user.id,RtUserFollow.following_id==target.id),and_(RtUserFollow.follower_id==target.id,RtUserFollow.following_id==user.id)))).all(): db.delete(follow)
    lo,hi=_rt_pair(user.id,target.id)
    friendship=db.scalar(select(RtFriendship).where(RtFriendship.user_a_id==lo,RtFriendship.user_b_id==hi))
    if friendship: db.delete(friendship)
    db.commit()
    return {"ok":True,"blocked":{"username":target.username,"display_name":target.display_name}}

@app.delete("/api/blocks/{username}")
def rt_unblock_user(username: str, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db)
    target=db.scalar(select(User).where(func.lower(User.username)==username.strip().lstrip("@").lower()))
    if not target: raise HTTPException(status_code=404,detail="That account could not be found.")
    row=db.scalar(select(RtUserBlock).where(RtUserBlock.blocker_id==user.id,RtUserBlock.blocked_id==target.id))
    if row: db.delete(row);db.commit()
    return {"ok":True}

@app.post("/api/mutes", status_code=status.HTTP_201_CREATED)
def rt_mute_user(body: RtBlockBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db)
    username=body.username.strip().lstrip("@").lower()
    target=db.scalar(select(User).where(func.lower(User.username)==username))
    if not target: raise HTTPException(status_code=404,detail="That account could not be found.")
    if target.id==user.id: raise HTTPException(status_code=400,detail="You cannot mute your own account.")
    if _rt_is_blocked(db,user.id,target.id): raise HTTPException(status_code=409,detail="Unblock this account before muting it.")
    existing=db.scalar(select(RtUserMute).where(RtUserMute.muter_id==user.id,RtUserMute.muted_id==target.id))
    if not existing: db.add(RtUserMute(muter_id=user.id,muted_id=target.id));db.commit()
    return {"ok":True,"muted":{"username":target.username,"display_name":target.display_name}}

@app.delete("/api/mutes/{username}")
def rt_unmute_user(username: str, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db)
    target=db.scalar(select(User).where(func.lower(User.username)==username.strip().lstrip("@").lower()))
    if not target: raise HTTPException(status_code=404,detail="That account could not be found.")
    row=db.scalar(select(RtUserMute).where(RtUserMute.muter_id==user.id,RtUserMute.muted_id==target.id))
    if row: db.delete(row);db.commit()
    return {"ok":True}

@app.post("/api/reports", status_code=status.HTTP_201_CREATED)
def rt_submit_report(body: RtReportBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db)
    if body.target_type=="post":
        target=db.get(RtPost,body.target_id)
        if not target: raise HTTPException(status_code=404,detail="The post could not be found.")
        if target.author_id==user.id: raise HTTPException(status_code=400,detail="You cannot report your own post.")
        target_user_id=target.author_id
    else:
        target=db.get(User,body.target_id)
        if not target: raise HTTPException(status_code=404,detail="The account could not be found.")
        if target.id==user.id: raise HTTPException(status_code=400,detail="You cannot report your own account.")
        target_user_id=target.id
    # Avoid duplicate pending reports from one reporter about the same target.
    existing=db.scalar(select(RtContentReport).where(RtContentReport.reporter_id==user.id,RtContentReport.target_type==body.target_type,RtContentReport.target_id==body.target_id,RtContentReport.status=="pending"))
    if existing: return {"ok":True,"report_id":existing.id,"message":"Your report is already with the moderation team."}
    row=RtContentReport(reporter_id=user.id,target_type=body.target_type,target_id=body.target_id,reason=body.reason.strip())
    db.add(row);db.flush()
    reviewers=db.scalars(select(User).where(func.lower(User.role).in_(["moderator","administrator","owner"]))).all()
    for reviewer in reviewers:
        if reviewer.id!=user.id: _rt_notify(db,reviewer.id,"New community report needs review.","report",row.id)
    db.commit();db.refresh(row)
    return {"ok":True,"report_id":row.id,"message":"Thank you. Your report has been sent to the moderation team."}

@app.get("/api/moderation/reports")
def rt_moderation_reports(request: Request, status_filter: str = "pending", db: Session = Depends(get_db)) -> dict:
    require_moderator(request,db)
    query=select(RtContentReport)
    if status_filter in {"pending","reviewed","dismissed"}: query=query.where(RtContentReport.status==status_filter)
    rows=db.scalars(query.order_by(RtContentReport.created_at.desc()).limit(100)).all();items=[]
    for r in rows:
        reporter=db.get(User,r.reporter_id)
        if r.target_type=="post":
            target=db.get(RtPost,r.target_id); target_user=db.get(User,target.author_id) if target else None; summary=(target.text[:240] if target and target.text else "Post media")
        else:
            target_user=db.get(User,r.target_id); summary=("@"+target_user.username) if target_user else "Deleted account"
        items.append({"id":r.id,"target_type":r.target_type,"target_id":r.target_id,"target_username":target_user.username if target_user else "deleted","target_display_name":target_user.display_name if target_user else "Deleted account","target_badges":active_account_badges(target_user),"summary":summary,"reason":r.reason,"status":r.status,"reporter":reporter.username if reporter else "deleted","reporter_badges":active_account_badges(reporter),"created_at":_rt_iso(r.created_at)})
    return {"items":items}

@app.patch("/api/moderation/reports/{report_id}")
def rt_review_report(report_id: int, body: RtReportStatusBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);reviewer=require_moderator(request,db);row=db.get(RtContentReport,report_id)
    if not row: raise HTTPException(status_code=404,detail="Report not found.")
    row.status=body.status;row.reviewed_by=reviewer.id;row.reviewed_at=datetime.now(timezone.utc);db.commit()
    _rt_notify(db,row.reporter_id,"Your report has been reviewed by the InnerCly moderation team.","report",row.id);db.commit()
    return {"ok":True,"status":row.status}

@app.get("/api/creator/analytics")
def rt_creator_analytics(request: Request, db: Session = Depends(get_db)) -> dict:
    user=require_rt_user(request,db)
    posts=db.scalars(select(RtPost).where(RtPost.author_id==user.id).order_by(RtPost.created_at.desc()).limit(100)).all()
    post_ids=[p.id for p in posts]
    total_posts=db.scalar(select(func.count(RtPost.id)).where(RtPost.author_id==user.id)) or 0
    likes=db.scalar(select(func.count(RtPostLike.id)).join(RtPost,RtPost.id==RtPostLike.post_id).where(RtPost.author_id==user.id)) or 0
    comments=db.scalar(select(func.count(RtPostComment.id)).join(RtPost,RtPost.id==RtPostComment.post_id).where(RtPost.author_id==user.id)) or 0
    followers=db.scalar(select(func.count(RtUserFollow.id)).where(RtUserFollow.following_id==user.id)) or 0
    views=db.scalar(select(func.count(RtPostView.id)).join(RtPost,RtPost.id==RtPostView.post_id).where(RtPost.author_id==user.id)) or 0

    # Aggregate metrics in three grouped queries rather than issuing three queries for every post.
    # This keeps the dashboard responsive as creators publish more content.
    def counts_by_post(model):
        if not post_ids:
            return {}
        result=db.execute(select(model.post_id,func.count(model.id)).where(model.post_id.in_(post_ids)).group_by(model.post_id)).all()
        return {int(post_id):int(count) for post_id,count in result}

    views_by_post=counts_by_post(RtPostView)
    likes_by_post=counts_by_post(RtPostLike)
    comments_by_post=counts_by_post(RtPostComment)
    ranked=[]
    for post in posts:
        pc=comments_by_post.get(post.id,0)
        pl=likes_by_post.get(post.id,0)
        pv=views_by_post.get(post.id,0)
        ranked.append({"id":post.id,"text":post.text[:120],"created_at":_rt_iso(post.created_at),"likes":pl,"comments":pc,"views":pv,"interactions":pl+pc})
    ranked.sort(key=lambda item:(item["views"]+item["likes"]+item["comments"],item["views"],item["likes"],item["comments"],item["created_at"] or ""),reverse=True)
    interaction_rate=round(((likes+comments)/views)*100,1) if views else 0.0
    return {"role":user.role,"can_view":True,"posts":total_posts,"posts_total":total_posts,"likes":likes,"comments":comments,"followers":followers,"views":views,"engagement_rate":interaction_rate,"top_posts":ranked[:10],"note":"Views count at most once per signed-in account per post per day; interaction rate is (likes + comments) divided by recorded views, not a reach or impression metric."}

@app.post("/api/chats/{username}/messages/{message_id}/reactions")
def rt_react_dm(username: str, message_id: int, body: RtReactionBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);other=db.scalar(select(User).where(func.lower(User.username)==username.strip().lower()))
    if not other or not _rt_are_friends(db,user.id,other.id) or _rt_is_blocked(db,user.id,other.id): raise HTTPException(status_code=404,detail="Chat unavailable.")
    message=db.get(RtDirectMessage,message_id)
    if not message or {message.sender_id,message.recipient_id}!={user.id,other.id}: raise HTTPException(status_code=404,detail="Message not found in this chat.")
    emoji=body.emoji.strip()
    if emoji not in {"👍","❤️","😂","😮","😢","🙏"}: raise HTTPException(status_code=422,detail="Choose a supported reaction.")
    row=db.scalar(select(RtMessageReaction).where(RtMessageReaction.message_type=="dm",RtMessageReaction.message_id==message_id,RtMessageReaction.user_id==user.id))
    if row and row.emoji==emoji: db.delete(row)
    elif row: row.emoji=emoji
    else: db.add(RtMessageReaction(message_type="dm",message_id=message_id,user_id=user.id,emoji=emoji))
    db.commit();return {"reactions":_rt_message_reactions(db,"dm",message_id,user.id)}

@app.post("/api/groups/{group_id}/messages/{message_id}/reactions")
def rt_react_group_message(group_id: int, message_id: int, body: RtReactionBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);member=db.scalar(select(RtGroupMember.id).where(RtGroupMember.group_id==group_id,RtGroupMember.user_id==user.id))
    message=db.get(RtGroupMessage,message_id)
    if not member or not message or message.group_id!=group_id: raise HTTPException(status_code=404,detail="Message not found in this group.")
    emoji=body.emoji.strip()
    if emoji not in {"👍","❤️","😂","😮","😢","🙏"}: raise HTTPException(status_code=422,detail="Choose a supported reaction.")
    row=db.scalar(select(RtMessageReaction).where(RtMessageReaction.message_type=="group",RtMessageReaction.message_id==message_id,RtMessageReaction.user_id==user.id))
    if row and row.emoji==emoji: db.delete(row)
    elif row: row.emoji=emoji
    else: db.add(RtMessageReaction(message_type="group",message_id=message_id,user_id=user.id,emoji=emoji))
    db.commit();return {"reactions":_rt_message_reactions(db,"group",message_id,user.id)}

@app.delete("/api/chats/{username}/messages/{message_id}")
def rt_delete_dm(username: str, message_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);other=db.scalar(select(User).where(func.lower(User.username)==username.strip().lower()))
    message=db.get(RtDirectMessage,message_id)
    if not other or not message or {message.sender_id,message.recipient_id}!={user.id,other.id}: raise HTTPException(status_code=404,detail="Message not found.")
    if message.sender_id!=user.id: raise HTTPException(status_code=403,detail="You can only delete your own messages.")
    db.delete(message);db.commit();return {"ok":True}

@app.patch("/api/chats/{username}/messages/{message_id}")
def rt_edit_dm(username: str, message_id: int, body: RtMessageEditBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);other=db.scalar(select(User).where(func.lower(User.username)==username.strip().lower()))
    message=db.get(RtDirectMessage,message_id)
    if not other or not message or {message.sender_id,message.recipient_id}!={user.id,other.id}: raise HTTPException(status_code=404,detail="Message not found.")
    if message.sender_id!=user.id: raise HTTPException(status_code=403,detail="You can only edit your own messages.")
    message.text=body.text.strip();message.edited_at=datetime.now(timezone.utc);db.commit();return {"ok":True,"text":message.text}

@app.delete("/api/groups/{group_id}/messages/{message_id}")
def rt_delete_group_message(group_id: int, message_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);member=db.scalar(select(RtGroupMember.id).where(RtGroupMember.group_id==group_id,RtGroupMember.user_id==user.id))
    message=db.get(RtGroupMessage,message_id)
    if not member or not message or message.group_id!=group_id: raise HTTPException(status_code=404,detail="Message not found.")
    if message.author_id!=user.id: raise HTTPException(status_code=403,detail="You can only delete your own messages.")
    db.delete(message);db.commit();return {"ok":True}

@app.patch("/api/groups/{group_id}/messages/{message_id}")
def rt_edit_group_message(group_id: int, message_id: int, body: RtMessageEditBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);member=db.scalar(select(RtGroupMember.id).where(RtGroupMember.group_id==group_id,RtGroupMember.user_id==user.id))
    message=db.get(RtGroupMessage,message_id)
    if not member or not message or message.group_id!=group_id: raise HTTPException(status_code=404,detail="Message not found.")
    if message.author_id!=user.id: raise HTTPException(status_code=403,detail="You can only edit your own messages.")
    message.text=body.text.strip();message.edited_at=datetime.now(timezone.utc);db.commit();return {"ok":True,"text":message.text}

@app.get("/api/media")
def rt_list_media(request: Request, db: Session = Depends(get_db)) -> dict:
    user=require_rt_user(request,db);rows=db.scalars(select(RtMediaAsset).where(RtMediaAsset.owner_id==user.id).order_by(RtMediaAsset.created_at.desc()).limit(100)).all()
    return {"items":[{"id":m.id,"filename":m.filename,"media_type":m.media_type,"data_url":m.data_url,"created_at":_rt_iso(m.created_at)} for m in rows]}

@app.post("/api/media", status_code=status.HTTP_201_CREATED)
def rt_upload_media(body: RtMediaBody, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);data=_rt_check_media(body.data_url,images_only=True,max_chars=600_000)
    subscription = db.scalar(select(RtPremiumSubscription).where(RtPremiumSubscription.user_id == user.id))
    if subscription and subscription.status == "active" and subscription.plan_code in LIFETIME_PLAN_CODES:
        current_chars = int(db.scalar(select(func.coalesce(func.sum(func.length(RtMediaAsset.data_url)), 0)).where(RtMediaAsset.owner_id == user.id)) or 0)
        incoming_bytes = len(data.encode("utf-8"))
        # data URLs are ASCII in current uploads; conservatively count their stored bytes.
        if current_chars + incoming_bytes > LIFETIME_STORAGE_CAP_BYTES:
            raise HTTPException(status_code=413, detail="Your lifetime membership includes up to 50GB of My Media storage. Delete older media or use a separate storage plan.")
    row=RtMediaAsset(owner_id=user.id,filename=body.filename.strip() or "image.jpg",media_type="image",data_url=data);db.add(row);db.commit();db.refresh(row)
    return {"item":{"id":row.id,"filename":row.filename,"media_type":row.media_type,"data_url":row.data_url,"created_at":_rt_iso(row.created_at)}}

@app.delete("/api/media/{media_id}")
def rt_delete_media(media_id: int, request: Request, db: Session = Depends(get_db)) -> dict:
    require_same_origin(request);user=require_rt_user(request,db);row=db.get(RtMediaAsset,media_id)
    if not row or row.owner_id!=user.id: raise HTTPException(status_code=404,detail="Image not found in your library.")
    db.delete(row);db.commit();return {"ok":True}
