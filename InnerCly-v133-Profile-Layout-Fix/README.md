# InnerCly v133 — Profile page layout fix

This is a narrowly scoped visual update to the profile page in the v132 package.

## What changed

- Added the missing desktop styling for the existing profile page markup.
- Styled the profile cover, avatar and actions, account details, post/friend/group statistics, Posts/About/Photos/Friends tabs, post composer, post cards, photo grid, and friend list.
- Kept the existing white and light-blue visual direction.
- Preserved the existing mobile profile styles.

## What did not change

No profile, authentication, session, database, feed, Stories, live-stream, search, notifications, messaging, friends, monetization, or payment logic was changed. The profile HTML and its existing event handlers are unchanged; this release adds scoped CSS and updates build-version metadata only.

## Run locally

1. Extract this ZIP into a new folder.
2. Run `START_INNERCLY.bat`.
3. Open the profile page on desktop and mobile widths and verify the Posts, About, Photos, and Friends tabs.

Do not open `index.html` directly; the app needs its API and database. Existing accounts/data are not included in this ZIP. Do not overwrite a known-working copy until you have tested this candidate.

The v40 and v80 master backup files are included unchanged.

## Deployment note

This ZIP does not update GitHub or Render automatically. Verify it locally before deployment.
