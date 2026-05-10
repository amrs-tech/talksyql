# talksyql

talksyql is a dependency-free Node.js web app that turns voice/audio or typed input into SQL. It supports anonymous use without storage, email-only user login for saved history, and a separate admin area for provider settings and data control.

## Project Status

talksyql is an experimental learning prototype. It is not production database advice, security advice, or a guarantee that generated SQL is safe for every schema. Always review generated SQL before running it against real data.

## Run

```bash
npm install
npm start
```

Open `http://localhost:4173`.

Local development uses `data/db.json` if `DATABASE_URL` is not set. Production must use Postgres.

## Admin Login

Set these environment variables for production:

```bash
NODE_ENV=production
DATABASE_URL=postgresql://user:password@host:5432/database
TALKSYQL_ADMIN_EMAIL=admin@example.com
TALKSYQL_ADMIN_PASSWORD=use-a-strong-password
TALKSYQL_SECRET=replace-with-a-long-random-secret
```

For local development, defaults are:

- Email: `admin@talksyql.local`
- Password: `change-me-now`

## Providers

Configure providers in the admin panel.

- ElevenLabs Speech to Text: `POST https://api.elevenlabs.io/v1/speech-to-text`, default model `scribe_v2`
- Gemini: `POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent`, default model `gemini-3.1-flash-lite-preview`
- Email OTP delivery: SMTP host, port, security mode, from email/name, username, and password.

Common SMTP examples:

- Gmail: host `smtp.gmail.com`, port `587`, security `STARTTLS`, username is the Gmail address, password is an app password.
- SendGrid: host `smtp.sendgrid.net`, port `587`, username `apikey`, password is the SendGrid API key.
- Amazon SES SMTP: use the region SMTP endpoint, port `587`, username/password from SES SMTP credentials.

## Storage Rules

- Anonymous users can transcribe and generate SQL, but their inputs/outputs are not stored.
- Email login sends a 6-digit OTP through the configured SMTP provider.
- Logged-in users have generated SQL saved in Postgres when `DATABASE_URL` is configured.
- Admin users can update provider settings, inspect users/history, and delete users/history.

## Security Limits

- OTP email requests: 3 requests per email/IP per 15 minutes, then a 15-minute lockout.
- User OTP verification: 5 incorrect attempts per email/IP in 10 minutes, then a 10-minute lockout.
- Admin login: 5 incorrect attempts per admin email/IP in 15 minutes, then a 15-minute lockout.
- Transcribe: 3 requests per minute per logged-in user, or per IP for anonymous users, then a 5-minute lockout.
- Generate SQL: 3 requests per minute per logged-in user, or per IP for anonymous users, then a 5-minute lockout.

Rate limits are persisted in Postgres when `DATABASE_URL` is configured and in local `data/db.json` during fallback development.

## Deploy on Render

This repo includes `render.yaml` for a Render web service plus Render Postgres.

1. Push the source to GitHub. Confirm `data/db.json` and `data/db.json.tmp` are not committed.
2. In Render, create a new Blueprint from the repository.
3. During Blueprint setup, provide:
   - `TALKSYQL_ADMIN_EMAIL`
   - `TALKSYQL_ADMIN_PASSWORD`
4. Render generates `TALKSYQL_SECRET` and injects `DATABASE_URL` from `talksyql-db`.
5. After deploy, open the Render URL and log in to Admin.
6. Configure Gemini, ElevenLabs, and SMTP settings in Admin.

Render settings used by the Blueprint:

- Build command: `npm install`
- Start command: `npm start`
- Health check path: `/api/health`
- Runtime: Node.js from `package.json` engines

Important: `TALKSYQL_SECRET` encrypts provider credentials stored in Postgres. Changing it after saving provider settings makes existing encrypted provider keys unreadable.

## Public Repository Safety

Never commit local secrets or runtime data. Keep these out of Git:

- `.env` and `.env.*` files, except `.env.example`
- `data/`
- provider API keys
- Gmail app passwords or SMTP passwords
- real `DATABASE_URL` values
- screenshots that expose secrets, provider settings, user emails, or database credentials
- local user/session/history data

Before pushing publicly, run:

```bash
git status --ignored
```

Confirm `data/`, `node_modules/`, and any real `.env` files are ignored.

## Security

Please report vulnerabilities privately. Do not post secrets, API keys, database URLs, auth bypasses, or exploit details in public issues.

See [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE).
