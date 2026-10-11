# AYUSH+

AYUSH+ organizes health records, extracts text from supported files, and offers optional AI explanations and spoken summaries. It is a prototype and has not been clinically validated. Do not use AI output to diagnose, prescribe, or make care decisions.

## Run locally

1. Install Node.js 22.13 or newer and run `npm install`.
2. Copy `.env.example` to `.env`.
3. Generate a 32-byte encryption key: `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`. Put the output in `.env` as `DATA_ENCRYPTION_KEY` and keep a secure backup. Losing the key makes stored health records unrecoverable.
4. In [Google Cloud Console](https://console.cloud.google.com/auth/clients), select or create a project, complete OAuth consent screen/branding, then create a Google Identity Services **Web application** OAuth client. Add the exact origin `http://localhost:8000` under **Authorized JavaScript origins** (no path). Copy the client ID ending in `.apps.googleusercontent.com` to `GOOGLE_CLIENT_ID` in `.env`. This sign-in flow does not use a client secret. Stop and restart the server after changing `.env`, then reload the page. For deployment, add the exact HTTPS origin there too. Google guide: https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid.
5. To enable optional AI text explanations and generated speech, create an OpenAI API key and set `OPENAI_API_KEY` in `.env`. `OPENAI_MODEL` must name a model available to that API project. Never put a provider key in frontend files or commit `.env`. If analysis fails, the app reports whether the provider rejected the key, model access, quota, or request; check the server terminal for a request ID if contacting provider support. API use may incur charges.
6. For full website translation, enable Cloud Translation Basic (v2) in a Google Cloud project, create a key restricted to that API, and set `GOOGLE_TRANSLATE_API_KEY` in `.env`. Translation is requested only for static interface labels and is proxied by the server; patient record text is excluded. Translation usage may incur provider charges. Without this key, the app uses its built-in translations for the main controls and navigation.
7. Run `npm start` and open the `http://localhost:<port>` address printed in the terminal (normally `http://localhost:8000`). Keep the server running while using the app. Do not launch `index.html` through VS Code Live Server or another static-file server: sign-in, encrypted uploads, and AI routes require the AYUSH+ Node server and will fail with HTTP 405 on a static server.

The workspace is hidden until account sign-in succeeds. Uploads require a signed-in account, the encryption key, and the upload consent checkbox. AYUSH+ extracts text in the browser, then stores the original file and account data in SQLite encrypted with AES-256-GCM under the signed-in account. Signed-in account data is held in memory in the browser and synchronized to the server rather than retained in browser local storage. The local `data/` directory is ignored by Git. Back up the database and encryption key securely.

**Do not use this prototype to collect real patient records.** Database encryption is not end-to-end encryption: the server operator controls the encryption key. The current app has no verified email/password registration or recovery, no production-grade audit/retention workflow, and no healthcare compliance certification. Production mode deliberately disables email/password demo accounts; the former `ALLOW_UNVERIFIED_EMAIL_AUTH` override is rejected. Before any public launch involving Indian users' real health information, complete an independent security assessment, India-specific privacy/regulatory review, and a production hosting, backup, incident-response, access-control, and data-deletion design. A production `NODE_ENV` setting alone does not make this app compliant or safe for patient onboarding.

## Supported file formats

- PDF: first 20 pages are rendered locally and OCR'd.
- PNG/JPG: local OCR.
- DOCX, XLSX, PPTX, ODT, ODS, ODP, ODG, EPUB and TEX: the signed-in server parses these after encrypted account upload using [officeparser](https://github.com/harshankur/officeParser).
- TXT, CSV, JSON, Markdown, HTML, RTF and LOG: text is read locally; HTML scripts/styles are removed; JSON is formatted.
- Each file is limited to 20 MB. Extracted text is capped at 200,000 characters. OCR and extraction can miss content or misread values. Legacy binary Office, password-protected/damaged files, embedded scans in Office docs, scanned-in-unsupported-language, proprietary binary, and other formats are not supported. No parser can reliably interpret every possible file format.
- OCR languages available: English, Hindi, Tamil, Telugu, Kannada and Malayalam (printed-script recognition); handwritten recognition is best effort and currently offered for English and Hindi.

## Optional AI and voice

The AI buttons send extracted document text to the server only after the user clicks an AI action and confirms the sharing prompt. The full-history action analyzes every readable record in the selected family profile in chunks (up to 600,000 extracted characters); it refuses oversized histories rather than silently dropping records. Report dates detected from the document text are included, with upload dates shown separately. The API key stays on the server. The app uses the [OpenAI Responses API](https://platform.openai.com/docs/api-reference/responses) for plain-language explanations and its [audio speech endpoint](https://developers.openai.com/api/docs/guides/text-to-speech) for generated voice in English, Hindi, Tamil, Telugu, Kannada or Malayalam. Voice pronunciation quality varies by language; OpenAI notes its voices are optimized for English, so South Indian voice quality must be reviewed with native speakers. Browser speech recognition and local speech voices depend on the device and browser.

For AI speech, the app prefers Google Cloud Text-to-Speech when `GOOGLE_TTS_API_KEY` is configured, with OpenAI speech as a fallback. Translation and speech are separate Google Cloud APIs. Enable Cloud Text-to-Speech, enable billing, create a server-side API key restricted to that API, and set `GOOGLE_TTS_API_KEY` in `.env`. Google documents voices for Hindi, Tamil, Telugu, Kannada, and Malayalam; check the current [voice list](https://docs.cloud.google.com/text-to-speech/docs/list-voices-and-types) and [pricing/free usage](https://cloud.google.com/text-to-speech/pricing). Do not put the key in frontend code or share it in chat.

OpenAI states that API content is not used to train models by default, while abuse-monitoring logs may retain content for up to 30 days unless an eligible organization is approved for different controls ([current data controls](https://developers.openai.com/api/docs/guides/your-data)). Review the provider's current data policy, obtain appropriate patient authorization, and complete legal/privacy review before sending real patient information to an external AI provider. `store:false` is set for text analysis; it does not remove all provider-side retention. AI output may be wrong and is not medical advice.

## Temporary public demo on Render

`render.yaml` prepares a free Docker web service in Singapore at `https://ayushplus-health-demo.onrender.com`. This service is for **synthetic test data only**: free instances can sleep when idle and wake slowly, and their local filesystem is ephemeral, so uploaded files and SQLite data can be lost on restart or redeploy. Do not upload real health information. OpenAI API use is billed separately by the provider.

1. Create a **private** GitHub repository and upload this project. Check that `.env`, `.env.production`, `data/`, `node_modules/`, and backups are not included. Never publish API keys or patient records.
2. In Render, create a Blueprint from that repository and deploy the `render.yaml` configuration. If Render assigns a different `onrender.com` hostname, update `PUBLIC_ORIGIN` in the service environment to the exact HTTPS origin and use that same origin in the OAuth setup below.
3. In the Render service's environment settings, set:
   - `GOOGLE_CLIENT_ID` to a Google Identity Services **Web application** client ID. Add the exact `PUBLIC_ORIGIN` to its **Authorized JavaScript origins**.
   - `DATA_ENCRYPTION_KEY` to a new base64-encoded 32-byte key generated with `node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"`. Keep it private; changing or losing it makes stored data unrecoverable.
   - `OPENAI_API_KEY` to a newly created, private API key if AI explanations are desired. Never reuse a key that may have been exposed. OpenAI API usage may incur charges.
4. Wait for Render's deploy and `/healthz` check to succeed, then open the Render URL. Sign in and test upload and AI analysis using synthetic files only. The app requires explicit consent before storing records and separately before sending extracted text to AI.

The free demo does not provide durable storage or guaranteed immediate availability. It is not a clinical service and is not approved for patient data.

## Single-VPS container deployment

The included Docker Compose setup is for **one VPS and one app instance**, with Caddy providing HTTPS and named volumes for SQLite, backups, and TLS certificates. It is not a multi-instance or high-availability deployment.

1. Provision a maintained Linux VPS. Point the chosen public DNS name (`A`, and `AAAA` only if IPv6 is correctly configured) at it. Allow inbound TCP 80/443 and SSH only from trusted administrator addresses in the provider firewall. Select the hosting region after privacy and legal review; this app does not enforce data residency.
2. Install Docker Engine and the Docker Compose plugin from the official Docker instructions for that Linux distribution. Clone/copy the project onto the VPS. Never copy your development `.env` file or a database with real records to the server as part of source deployment.
3. Create the private production environment file and set restrictive permissions:

   ```sh
   cp .env.production.example .env.production
   chmod 600 .env.production
   ```

   Set `PUBLIC_DOMAIN`, the matching exact `PUBLIC_ORIGIN` (`https://...`), `ACME_EMAIL`, a Google Web OAuth client ID, and a fresh base64-encoded 32-byte `DATA_ENCRYPTION_KEY`. Generate the encryption key with:

   ```sh
   node -e "console.log(require('node:crypto').randomBytes(32).toString('base64'))"
   ```

   Keep a secure, access-controlled backup of that key **separately** from the database. Losing or changing it without a tested re-encryption migration makes stored data unrecoverable. Set external provider API keys only if those features are deliberately enabled; restrict keys to the required APIs and set provider quotas/billing alerts.
   
   After editing `.env.production`, run `npm run preflight:production` from the project directory. It checks production mode, exact HTTPS/domain matching, OAuth client ID shape, the encryption key format, and optional provider configuration without printing secret values. Fix every reported error before deployment; review warnings against the features you intend to offer.
4. In Google Cloud Console, configure the production OAuth consent screen and add the exact HTTPS origin to the Web client's **Authorized JavaScript origins**. No path or trailing slash. Keep only the expected production origins.
5. Validate and start (do not print or paste `.env.production` contents into logs or support requests):

   ```sh
   docker compose --env-file .env.production config --quiet
   docker compose --env-file .env.production up -d --build
   docker compose --env-file .env.production ps
   docker compose --env-file .env.production logs --tail=100 app proxy
   ```

   Caddy obtains/renews certificates automatically. The app is not published directly to the host; only the proxy publishes ports 80/443. Do not add an app port mapping or expose the internal Docker network. Production startup fails closed if HTTPS origin, encryption key, Google client, or trusted-proxy configuration is missing, and it rejects unverified email authentication.
6. Test sign-in, uploads using synthetic files, account deletion, HTTPS renewal, restart persistence, and restore procedures before announcing the site. Confirm the browser resolves only the intended HTTPS domain and review provider/hosting logs without recording health data or secrets.
7. Create and export an encrypted database backup regularly:

   ```sh
   docker compose --env-file .env.production exec -T app node scripts/backup.js
   ```

   Backups are created in the `app_backups` Docker volume. Copy them to an encrypted off-site destination with restricted access, define and enforce a retention schedule, and periodically test restoring a copy together with the correct encryption key. Docker volumes on the VPS are **not** off-site backups. Preserve the encryption key separately. Do not run `docker compose down -v`; `-v` deletes the database, backups, and TLS certificate volumes.

The production file `.env.production` is ignored by Git. Do not paste it into chat or include it in build artifacts. Use a secrets manager instead of a file when the hosting environment supports one. Keep Docker, the OS, and the Caddy image updated; monitor disk capacity and service health. This setup does not configure an external intrusion-detection service or a backup-retention policy for you.

Google OAuth and OpenAI credentials must be supplied by the operator. The ABHA/FHIR features are still a local prototype; they do not connect to ABDM. Real ABDM integration requires approved sandbox access, registered callbacks, server-side credentials and conformance testing. No Aadhaar or OTP should be entered into this app.

The container setup only makes the website deployable for controlled testing. This codebase remains **not certified or ready for clinical production use**. Before onboarding patients, commission independent security testing and India-specific privacy/legal review, validate extraction and translations with clinicians and native speakers, establish consent/retention/deletion policies, implement audit trails and operational monitoring, and obtain all required regulatory approvals. Confirm external AI processing and data location are appropriate before enabling provider keys. The prototype's database and hosting configuration are not a substitute for a healthcare-grade deployment review.

## Demo account sign-in

Email/password accounts can be created from the sign-in screen in local development without a Google OAuth client. Passwords are scrypt-hashed, credential records and sessions are encrypted with `DATA_ENCRYPTION_KEY`, and session cookies are HTTP-only. Use a unique password. This demo does not verify email ownership or provide password recovery. Email/password demo accounts are always disabled in production, and startup rejects `ALLOW_UNVERIFIED_EMAIL_AUTH=true`. Configure a verified authentication and recovery provider before production use. Google sign-in remains optional and needs the Web client ID described above.