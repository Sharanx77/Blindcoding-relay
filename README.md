# Signal/Noise — Blind Coding Challenge

A React + TypeScript/Vite participant and organiser app. Local development uses Express, Socket.IO, and SQLite (sql.js); Vercel production uses serverless REST endpoints and Neon Postgres so room state and timers persist across function invocations.

## Run locally

Requirements: Node.js 22 and npm 10+.

```powershell
npm install
Copy-Item .env.example .env
# Set ADMIN_PASSWORD and ADMIN_TOKEN_SECRET in .env
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). The API server listens on port `3001`; Vite proxies `/api` to it. In development, the organiser password defaults to `dev-only-change-this` if `ADMIN_PASSWORD` is unset; configure a private value before sharing the app.

For the local production build:

```powershell
npm run build
npm start
```

The Express server serves `client/dist` alongside the API. This local build is useful for testing the single-process deployment; the Vercel build is described below.

## Deploy to Vercel

Vercel hosts the Vite frontend and the serverless API. Neon Postgres is required for persistent production storage; do not rely on a local SQLite file or function memory for event data.

1. Push the project to a GitHub repository and import it into Vercel. Keep the project root as the Vercel **Root Directory**.
2. Create a Postgres database in [Neon](https://neon.tech). Copy its pooled connection string (with SSL enabled) for `DATABASE_URL`.
3. Add these environment variables in **Vercel → Project → Settings → Environment Variables** for Production (and Preview if needed):
   - `DATABASE_URL`: the Neon connection string.
   - `ADMIN_PASSWORD`: a private password with at least 12 characters.
   - `ADMIN_TOKEN_SECRET`: a private random value with at least 32 characters. Generate one locally, for example with `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"`. Never share or commit this value.
4. Deploy. `vercel.json` builds the frontend and routes `/api/*` to the serverless function. The database schema is created automatically on the first API request. No separate migration or seed command is required; the three starter challenge templates ship with the API.
5. Open the Vercel URL and use the configured password under **Organiser Access**.

For local development, `.env` continues to use SQLite and the local Express server. Set `ADMIN_PASSWORD` and `ADMIN_TOKEN_SECRET` there as well. You do not need to put `DATABASE_URL` in local `.env` unless you specifically want to connect local tooling to Neon. Never commit `.env`; `.env.example` contains placeholders only.

Vercel room updates use short-interval polling instead of a persistent Socket.IO connection. The round deadline, participant drafts, and scores are stored in Neon. A timed-out round is finalized on the next API request; active rounds therefore do not depend on a background process or an in-memory timer.

## Event rules

| Round | Name | Time | Maximum |
|---|---|---:|---:|
| 1 | Type Before Time Runs Out | 30 seconds | 10 points |
| 2 | Blind Code Master | 45 seconds | 20 points |
| 3 | Decode, Type & Win | 60 seconds | 30 points |

The score is `round maximum × accuracy`; speed adds no points. Accuracy is calculated from Levenshtein edit distance against the exact reference, including spaces, line breaks, punctuation, and symbols. The server caps challenge and submitted text at 10,000 characters.

The organiser signs in with the configured password, creates a room, edits each round's reference and duration, shares the generated six-character code, and controls each round from the live console. Round durations can be set from 5 to 3,600 seconds. Participants register with a display name and USN; USNs are unique within each room. Results and challenge text are persisted in `server/data/challenge.sqlite`.

Completed events appear in the organiser's event history. Organisers can inspect participants and round-by-round results, rename a completed event, or permanently delete it with its associated participants and scores. Event names can only be changed after completion; deleting a non-completed event is blocked.

## Notes

- The game clock and evaluation run on the server. Participant drafts are sent through an authenticated endpoint while a round is active; only aggregate participant data and finalized scores are returned to clients.
- The participant editor masks visible characters and prevents normal paste, copy, cut, drag/drop, and context-menu interactions. Browser-side controls are user-interface deterrents, not a substitute for supervised event rules or a locked-down kiosk.
- The development seed challenges are inserted automatically on first startup. `npm run seed` restores/reseeds the three sample templates.
- In local SQLite development, completed scores and room definitions are restored after restart; interrupted unfinished rounds return to their lobby state and draft text is not persisted. On Vercel, active rounds and drafts persist in Neon.
- Existing databases are migrated at startup to add per-round timing and participant USN storage. Participants who only exist in older score rows receive a generated `LEGACY-…` USN in the event history.
