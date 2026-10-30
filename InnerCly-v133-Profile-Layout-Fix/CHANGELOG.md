## v133 — Desktop profile layout polish (2026-10-30)

- Added scoped desktop styles for the existing profile page markup.
- Restored styled profile cover, avatar/actions, stats, tabs, composer, posts, About rows, photos grid, and Friends list.
- Preserved mobile styles and existing application handlers. No feature logic was changed.

## v132 — Group chat composer polish (2026-10-30)
- Reworked the group-chat message composer into a responsive layout: message field, Attach photo, voice recording (Stop appears only while recording), attachment/recording status, and Send.
- Kept existing message, media upload, voice-note recording and send handlers and element IDs intact. Other app areas are not intentionally changed.

## v131 — Live video feed and mobile profile editing (2026-10-30)
- Home live cards now render a video element, show the creator's own camera preview in their own Home feed, and automatically connect the first shared creator stream as a muted inline preview for viewers. The front-facing camera is preferred for face-to-camera streaming; sound can be enabled with the video controls.
- Preserved the active Home live player during 12-second feed polling so the attached MediaStream is not destroyed by replacing the card markup. Home now reattaches an existing viewer stream when navigating from the separate Live viewer.
- Buffered early WebRTC ICE candidates until a remote description is installed and hardened remote track attachment for browsers that omit `event.streams`.
- Added persisted profile biography editing (280 characters) and safe migration for existing databases. The mobile Edit Profile actions open the editor directly; display name, username, bio and profile picture can be updated and are reflected on public profiles.
- Updated app/API/launcher build identifiers to v131. v40/v80 master backups are unchanged.
- Validation: Python compilation, 15 inline JavaScript syntax checks, new/old-database profile API tests, WebSocket signaling relay test, build marker test and ZIP integrity test passed. Real camera-to-camera playback on physical mobile devices was not available in this environment. STUN-only WebRTC may still need TURN for some mobile networks.

## v130 — Mobile notifications, search and member profile fixes (2026-10-30)
- Notification toast messages now sit above the fixed mobile bottom navigation and account for device safe-area insets.
- The header search now routes queries into the existing server-backed Discover search for people, posts, groups and Marketplace instead of searching only the currently rendered page text.
- Discover People and post results expose a visible View profile action; other members’ avatars and account names also open their public profiles.
- Fixed the empty public-profile posts state so profiles without posts show a clear message.
- Updated the API build marker, launcher validation and release README to v130. No Stories, login/session, live streaming, Premium or monetization logic was changed.
- v40/v80 backup files were carried forward byte-for-byte.

## v128 — urgent live-feed and navigation icon correction (2026-10-30)
- Live feed visibility is enabled by default for newly started streams; creators can untick it to keep a stream off Home.
- Home live-feed refresh now keys off the actual visible Home panel, avoiding stale route-state suppression.
- Home feed polling is no longer suppressed while a viewer is connected.
- Inline Home viewing no longer opens the separate “Watching live” viewer panel.
- Replaced generic text glyphs with purpose-matched SVG icons for Discover, Creator Dashboard, Live Streaming, Safety & Privacy, and Notifications.
- Validation: Python compile passed; 13 inline JavaScript blocks passed Node syntax checks; ZIP integrity checked after packaging. Live camera/WebRTC behavior still requires a real HTTPS two-account test; TURN relay is not configured in this build.


## v127 — Inline Home-feed live video and Kilos gifts

- Home-feed live cards now include an inline video player. Selecting Watch & send Kilos connects the viewer to the active WebRTC stream in that feed card instead of only showing a text announcement or navigating away.
- Kilos gift controls appear with the inline player and continue using the existing server-side gift endpoint and creator/platform split.
- The active inline live card is protected from the 12-second feed refresh while being watched, preventing the player element from being replaced during playback. Leaving the stream releases the video tracks and restores normal refresh behavior.
- No changes to the upper navigation/layout, Stories, login/session flow, Premium entitlements, monetization rules, or database schema. v40/v80 backups carried forward unchanged.
- Browser-to-browser video playback still requires real HTTPS testing; STUN-only WebRTC may fail on restrictive networks and can require TURN.

## v127 — Home-feed Live sharing and Premium session reliability

- Added creator-controlled consent to show a live stream in the Home feed, with a setting to change visibility while live.
- Home feed now refreshes opted-in live streams and links directly to watching and Kilos gifts; ending a stream removes it from the active list.
- Premium profile and chat preferences now load at account startup and revert to default appearance when Premium access is inactive.
- Existing Stories, feed posts, login/session flow, and v40/v80 backups were not intentionally changed. Live video itself still needs real two-browser HTTPS testing.

## v125 — Monetization strategy alignment

- Updated Premium pricing to $4.99 monthly, $49 annual, $149 lifetime, plus a $99 Founding Member lifetime offer capped at 500 checkout reservations.
- Added digital/physical Marketplace product classification and 10%/5% commission logic, with a 50% eligible exclusive-hub fee reduction.
- Added configurable Early Adopter creator eligibility for 90/10 Kilos gifts during the first account year; standard remains 80/20.
- Added 50GB My Media cap for lifetime memberships and documented lifetime benefits/marketplace exclusions.
- Preserved existing layout, Stories/player logic, login/session flow, and v40/v80 master backups. Checkout still requires Stripe configuration. Fan subscriptions and paywalled-content checkout are not separate purchase flows yet.

## v125 — Premium, Kilos, monetisation and Follow button fix

- Includes the chosen Premium plans ($2.99 monthly, $29 for three months, $129 lifetime), free Premium entitlement for active verification badges, Kilos wallet/purchases/gifts, basic live streaming, creator earnings and payout requests, Owner monetisation dashboard, 55/45 ad revenue split, and 5% Marketplace commission with actual Stripe processing fees deducted from seller proceeds.
- Follow buttons across Friends search/lists, inline post controls, and Discover/creator cards use explicit followed state, prevent duplicate taps while requests are pending, and retain the successful relationship change when a later UI refresh fails.
- Build identifiers updated to v125. Stories player and upper layout are intentionally unchanged. v40 and v80 master backups are carried forward unchanged.

## v123 — Premium, Kilos and monetisation foundations
- Added the selected Premium package ($2.99 monthly, $29 for three months, $129 lifetime), with free Premium eligibility for active blue/purple/gold/green verification badges and the Owner account. Premium cannot grant verification by itself.
- Added Premium profile themes, Premium Story effects, Creator Growth analytics, personal chat themes, and early-access entitlement. Ad removal and early-access catalogue integration remain entitlement markers until ad slots and rollout controls exist.
- Added Kilos wallets/ledger, server-verified Stripe Checkout completion, virtual gifting with an 80% creator / 20% platform split, and recorded Kilos pack pricing margin while delivering every purchased Kilo.
- Added basic WebRTC Live surfaces and signaling, creator earnings, payout-request reservation/review, and Owner-only monetisation reporting. External payouts remain manual; streaming has not been validated at scale and needs TURN/SFU for robust larger streams.
- Added 55% creator / 45% Owner traditional-ad accounting and USD Marketplace card checkout that uses Stripe's actual balance-transaction fee and a 5% gross-sale commission. Other Marketplace currencies retain the existing message/delivery flow.
- Added Marketplace Buy with card action for qualifying USD listings. Stripe payments remain disabled until `STRIPE_SECRET_KEY` and `STRIPE_WEBHOOK_SECRET` are configured on the host and tested in Stripe test mode.
- Kept v40/v80 backup artifacts unchanged. This source ZIP does not deploy or push changes to the hosted URL automatically.

## v122 — Profile CSS rendering correction
- Moved the appended v115 responsive stylesheet inside the HTML document before the closing body/html tags.
- Closed the `small` element in the Profile → About → Display name row.
- Limited changes to index markup and build metadata; existing features carried forward.

## v121 — Keep app background clear behind creation panels
- Updated only the Create Post, Create Story, and Create Group modal surface styling.
- Removed the dimming/blur effect from behind those creation panels and the Story camera overlay; the app behind them stays unchanged.
- Preserved Story viewer/playback styles and live-video mode.

## v121 — Make creation designs consistent across app modes

- Fixed the actual local/offline fallback post composer, which was still opening the old form.
- Fixed the fallback Story composer to use the same modal styling, media drop zone, caption field, and existing Story-save callback.
- Fixed the fallback Create Group flow to open the matching styled modal while using the existing local group-save logic.
- Kept the server-backed dialogs, camera Story creator, media/player logic, authentication, header/navigation, and feed handlers intact.
- Updated the local launcher and API build marker to v121.

## v119 — Create Post, Story, and Group design polish

- Reworked the live Create a post modal to match the supplied white/light-blue reference, with a 500-character counter, public/friends visibility, drag-and-drop media area, visible file selection status, voice-note controls, and expandable media library.
- Restyled the Story camera panel to match the provided camera layout: light panel, blue effect controls, live-camera badge, top-right flip-camera shortcut, caption/mentions, and responsive controls. Existing capture and recording handlers are preserved.
- Reworked the Create group dialog to match the same style and improved the Groups/Circles card treatment. Existing group API submit/reload logic is preserved.
- Kept the upper navigation/layout, section animations, logo assets, Story viewer/player, authentication and existing data routes unchanged.
- Updated local launcher/API build marker to v121.

## v118 — Section animations and cleaner opening sequence

- Added a subtle 260 ms fade-and-lift transition whenever an app section opens, using opacity and transform only.
- Respects the device/browser reduced-motion preference by disabling the new section animation.
- Removed the visible “ENTER INNERCLY” button from the opening animation; the existing automatic dismissal and keyboard dismissal remain.
- No Story renderer/player code, navigation structure, upper layout geometry, database behavior, or feature logic was changed.
- Preserved the v40 and v80 master backups unchanged.

## v114 — Story and Home initialization recovery

- Fixed a scope error in the standalone account-header synchronization helper: it referenced `runtime`, `esc`, and `accountBadgeMarkup` from another script callback's lexical scope. This could throw during authenticated startup and prevent Home/Stories initialization from finishing.
- The helper now uses `window.__INNERCLY_REALTIME__`, `window.__INNERCLY_ACCOUNT_BADGE_MARKUP__`, and its own HTML escaping function.
- Story creation, playback, rendering, camera/capture flow, and Story CSS were not edited. The v40 and v80 master backups remain unchanged.

## v113 — Home feed refresh reliability

- Fixed an overlapping-request race in `refreshPosts`: the newest request started no longer cancels an older successful response if the newest request fails. Once a newer response successfully applies, older responses are ignored.
- Malformed feed responses are treated as errors rather than valid empty feeds, preventing cached posts from being cleared by an incomplete payload.
- Initial Home feed fetch retries twice after short delays while cached content remains visible, reducing the chance that a brief startup/network race leaves the feed incomplete.
- Exposed the canonical refresh function to existing feature integration helpers.
- No changes to the Stories renderer or upper app layout. The v40/v80 master backups are unchanged.

## v112 — Session-hint recovery and Home feed reload
- Fixed a concrete stale-session hint risk: the page bootstrap previously read `sessionStorage` before `localStorage`, while the auth flow writes `localStorage` first. If a stale tab hint survived a failed sessionStorage update, the page could repeatedly select the wrong state namespace after reload and leave the Home feed stale or incomplete.
- The early bootstrap and session-hint reader now compare both stores and prefer the newest timestamped hint; older hints fall back to localStorage.
- If the durable hint write succeeds but writing sessionStorage fails, the app removes the stale tab hint when possible.
- Added no changes to the Stories renderer or the upper app layout. v40/v80 master backups are unchanged.

## v111 — Authenticated startup blank-screen recovery

- Fixed a concrete recovery flaw carried in v109/v110: if `startRuntime()` set the realtime `ready` flag and then threw before a view was activated, the recovery path skipped its retry, hid the sign-in overlay, and reported success. That could leave the app looking empty.
- Recovery now retries authenticated runtime activation even when `ready` is already true, and makes the existing Home view visible if startup leaves every `.view` inactive.
- If authentication is valid but rendering still has a problem, the user stays signed in and gets a visible notice instead of an empty screen or a false request to sign in again.
- The Stories renderer and upper app layout were not changed by this patch; v40/v80 master backups are unchanged.

## v110 — Consistent build identification

- Corrected the stale sign-in-screen label from `INNERCLY BUILD · V107` to `INNERCLY BUILD · V110`. The previous v109 package already reported v109 through its API and launcher, but the leftover visible label made it look like v107 was opening.
- Aligned the browser title, API build values, launcher-required build, launch URL cache-buster, and launcher status messages to v110.
- Carried forward the v109 session-restoration handling and other app features without intentional changes to their behavior.
- Preserved the v40 and v80 master backups byte-for-byte.

## v109 — Session restoration error handling

- Fixed a startup-path bug that could treat a client-side app initialization exception as a failed saved login, even when `/api/auth/me` had already confirmed the server session.
- Added limited retries for transient connection/server errors during session restoration.
- A real HTTP 401 still opens the sign-in prompt. Other HTTP errors now show their status and do not claim the session was lost or ask the user to sign in as though the password were wrong.
- Kept changes limited to session restoration messaging/flow and version identifiers; feature layout and behavior elsewhere were not intentionally changed.
- v40 and v80 backup files were carried forward unchanged.

## v108 — Stable local session origin

- Traced the repeated-login path in the saved v107 project. The server session is stored in an HttpOnly cookie scoped to the exact local host and port; the launcher previously could silently choose a different port when the remembered port was occupied, making the saved cookie unavailable at the new address.
- The launcher now keeps the remembered local port stable and warns instead of silently switching to a different origin when an unrelated process occupies it. If an InnerCly server is detected, existing safe replacement behavior is retained.
- No login UI, feed, Stories, badges, or social features were changed. v40 and v80 backup files are preserved unchanged.

## v107 — Session restoration and immediate Home feed

- Fixed local HTTP cookie security by basing the cookie Secure attribute on the actual request origin; loopback HTTP does not receive an unusable Secure cookie.
- Start server-session validation while the existing intro animation is playing so Home/feed loads in parallel.
- Check that the newly issued server cookie authenticates successfully before forcing the account-state reload; display a clear error when cookie persistence cannot be confirmed.
- Render the current account's compact cached feed immediately, then replace it with the fresh server response. Large inline media is excluded from the cache to avoid browser storage exhaustion.
- Kept header/top-navigation markup and app layout structure unchanged. Badge management from v105 remains present.
- Preserved v40 and v80 master backups byte-for-byte.

## v105 — Restore session persistence and instant Home feed

- Kept the v104 global badge rendering and dedicated badge-management page.
- Local launcher now reuses a running v105 server only when it confirms local-development cookie settings; it replaces a misconfigured server that would issue Secure cookies over HTTP.
- Authentication restoration no longer lets a transient second check reopen the login overlay after a session is already active.
- Home is selected after session restoration; the feed placeholder renders immediately and the post list appears as soon as the posts API returns, without waiting for unrelated sections.
- Preserved the existing header/navigation structure and all original features.
- Left v40 and v80 backup files unchanged.

## v104 — Active badges displayed across InnerCly

- Added a shared account-name badge formatter used across posts, comments, friend lists and requests, followers, Discover, profiles, group/event owners, group/direct/marketplace/delivery chats, Marketplace sellers, moderation safety lists, and owner role/badge search results.
- Stories now retain badge data from the API and display active badges on story cards.
- Standardized active-badge serialization and included it in story, owner user-search, blocked-user, and muted-user responses so those surfaces have the data needed to display badges.
- Kept the dedicated Creator Verification & Badges page and the existing Roles & Permissions controls.
- Kept v40 and v80 master backup files unchanged.

## v104 badge-visibility additions

- Covered top account name/header refresh after sign-in, profile updates, and an Owner granting a badge to their own account.
- Added safe self-account badge rendering to the legacy local feed comments, Marketplace seller/order cards, and local seller/order chat labels.
- Added active badge data to moderation report targets and reporters so the Safety UI can render them.

## Validation

- Python syntax checked.
- Inline JavaScript syntax checked.
- ZIP integrity checked.
- Isolated API badge-grant smoke test passed in v104.


## v115 — Reels, Circles, Saved, Notifications, Creator Dashboard polish

- Replaced the local-only Reels gallery with a server-backed vertical video feed using existing post visibility, block, mute, and permission checks; added muted visible-card playback, pause-on-scroll, view tracking, like/comment/save/share/follow/report/delete actions, retry and empty states.
- Renamed the Groups view heading to Circles and added client-side search plus All/Joined/Created-by-me filters, without changing the existing group database or chat flows.
- Added search and collection filters to Saved; all save entry points now use a consistent collection picker.
- Added unread notification filtering, read-all, and navigation to related posts/chats/groups and other supported features.
- Improved creator analytics to show total post count, measured interaction-per-view rate, and posts ranked by recorded activity.
- Kept the Stories renderer/player and upper UI structure intact apart from the existing build marker text. The safety/privacy controls were already implemented and were not rewritten.


## v116 — Original logo fix
- Replaced the circular blue logo treatment on the opening and sign-in screens with the supplied full-logo artwork.
- Kept the compact header and landing page in their existing dimensions, using the original square-corner mark with the existing blue wordmark.
- Removed circular clipping/rings from active brand-mark displays.
- Updated the app build marker and Windows launcher check to v116 so it will not silently reuse a running v115 process.
- Did not modify Stories functionality, authentication logic, database logic, upper layout structure, or the v40/v80 backup files.


## v117 — Circular logo correction
- Corrected v116, which mistakenly changed the logo back to a square-corner treatment.
- Added a transparent circular-mask PNG derived from the existing InnerCly icon.
- Restored circular logo display on the phone/desktop header, opening screen, sign-in screen, verified-creators panel, and landing page.
- Preserved the existing wordmark, upper layout geometry, Stories renderer/player, login/database logic, and v40/v80 backup files.

## v129 — Public member profiles
- Added authenticated public profile retrieval by username, including profile identity, active badges, visible posts, and follower/following/friend counts.
- Added profile viewing from account names throughout the app and a direct View profile action in Discover search results.
- Added Follow, Add friend, and Message actions where the existing relationship state permits them.
- Respects existing public/friends-only post visibility and block rules; does not expose private posts to non-friends.
- Kept the existing profile editor and personal profile page unchanged.
