# MyWeb

A privacy & security web application featuring a private search engine, VPN/password-manager landing page, AI-resistant image protection, and a per-user privacy dashboard.

## Stack
- **Backend**: Node.js 20 + Express
- **Database**: PostgreSQL (Replit managed) via `pg`
- **Auth**: `express-session` + `connect-pg-simple` (7-day cookie, sessions in DB)
- **Image processing**: `sharp` + `multer`
- **Static files**: served from `public/` by Express

## Pages
| Route | Description |
|---|---|
| `/` | Landing page (index.html) |
| `/search` | Private search engine (no sign-in needed) |
| `/signup` | Account creation |
| `/login` | Sign in |
| `/dashboard` | Privacy dashboard (auth required) |
| `/protect` | AI-resistant image protection tool |
| `/privacy` | Privacy Policy |
| `/tos` | Terms of Service |

## Key API routes
- `POST /api/signup` — create account
- `POST /api/login` — authenticate
- `POST /api/logout` — end session
- `GET  /api/me` — current user info + settings
- `POST /api/settings` — save privacy toggles
- `GET  /api/search?q=&page=` — private web search (Yahoo proxy)
- `POST /api/protect-image` — apply AI-resistant noise to uploaded image

## DB tables
- `users` — id, email, password_hash, plan, created_at
- `user_settings` — per-user privacy toggles (tracker_blocking, https_upgrade, etc.)
- `session` — express-session persistence

## Design system
- Dark red theme: `--bg:#0d0505`, `--primary:#e03030`, `--surface:#180a0a`
- Font: Inter
- Icons: Font Awesome 6

## User preferences
- Red-oriented color scheme throughout
- Features should be "complete" and functional (no mocks/placeholders)
- Direct, casual communication style — results over explanation
- Remember everything across sessions
