HAZARD 7007 — BLUE EDITION

Included:
- dark mobile interface with blue outlines/accents;
- owner-only admin panel (password from environment variable);
- owner-created single-use invitations (24-hour expiry by default);
- after first activation, invite is consumed and an HttpOnly browser session is issued;
- owner can view devices and revoke any device session;
- SQLite persistence across server restarts.

IMPORTANT LIMITS
This binds access to the browser's HttpOnly cookie, not to an unforgeable physical device identity. A technically skilled user can copy browser session data. For stronger device binding, add passkeys/WebAuthn or verified account login. The UI controls are a visual simulator: real siren/radio/audio hardware is not connected.

DEPLOY
1. Use a Node.js 20+ host with persistent disk/volume (SQLite file must persist).
2. Upload the contents of this folder.
3. Run: npm install
4. Set environment variables:
   NODE_ENV=production
   ADMIN_PASSWORD=a-long-random-password-at-least-14-characters
   SESSION_SECRET=a-random-secret-at-least-32-characters
   PORT=3000 (or host-provided port)
   DB_FILE=./hazard.sqlite
5. Start: npm start
6. Use HTTPS. Open the deployed site and tap “Панель администратора”.

Invites expire after 24 hours. Only the first activation succeeds. Admin session lasts 7 days; member browser session lasts 1 year unless revoked. Keep the admin password and SESSION_SECRET private. Back up hazard.sqlite.
