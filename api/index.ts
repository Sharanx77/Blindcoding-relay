import { randomInt, randomUUID, createHmac, timingSafeEqual } from "node:crypto";
import { neon, type NeonQueryFunction } from "@neondatabase/serverless";
import { z } from "zod";
import { isValidAdminToken, issueAdminToken } from "../server/src/auth.js";
import { CHALLENGE_SEEDS, ROUND_CONFIG } from "../server/src/challenges.js";
import { evaluateSubmission } from "../server/src/scoring.js";
import type { RoomStatus, RoundNumber } from "../server/src/types.js";

type NeonClient = NeonQueryFunction<false, false>;
type Row = Record<string, unknown>;

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}

let client: NeonClient | undefined;
let schemaReady: Promise<void> | undefined;

const challengeSchema = z.object({
  round: z.union([z.literal(1), z.literal(2), z.literal(3)]),
  referenceText: z.string().min(1).max(10_000),
  duration: z.number().int().min(5).max(3600).optional()
});

const createRoomSchema = z.object({
  name: z.string().trim().min(2).max(60),
  challenges: z.array(challengeSchema).length(3).refine(
    (challenges) => new Set(challenges.map(({ round }) => round)).size === 3,
    "Include one challenge for each round."
  )
});

function getClient(): NeonClient {
  if (client) return client;
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) throw new HttpError(503, "Database is not configured. Set DATABASE_URL in Vercel.");
  client = neon(connectionString);
  return client;
}

async function ensureSchema(): Promise<NeonClient> {
  const db = getClient();
  schemaReady ??= db.transaction([
    db`SELECT pg_advisory_xact_lock(hashtext('blind_coding_challenge_schema_v1'))`,
    db`CREATE TABLE IF NOT EXISTS rooms (
      code TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('lobby', 'running', 'paused', 'finalizing', 'between_rounds', 'completed')),
      round INTEGER NOT NULL CHECK (round BETWEEN 1 AND 3),
      remaining_ms BIGINT NOT NULL DEFAULT 0,
      ends_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
    db`CREATE TABLE IF NOT EXISTS room_challenges (
      room_code TEXT NOT NULL REFERENCES rooms(code) ON DELETE CASCADE,
      round INTEGER NOT NULL CHECK (round BETWEEN 1 AND 3),
      reference_text TEXT NOT NULL,
      duration_seconds INTEGER NOT NULL CHECK (duration_seconds BETWEEN 5 AND 3600),
      PRIMARY KEY (room_code, round)
    )`,
    db`CREATE TABLE IF NOT EXISTS participants (
      id UUID NOT NULL,
      room_code TEXT NOT NULL REFERENCES rooms(code) ON DELETE CASCADE,
      name TEXT NOT NULL,
      usn TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (room_code, id),
      UNIQUE (room_code, usn)
    )`,
    db`CREATE TABLE IF NOT EXISTS submissions (
      room_code TEXT NOT NULL,
      participant_id UUID NOT NULL,
      round INTEGER NOT NULL,
      text TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (room_code, participant_id, round),
      FOREIGN KEY (room_code, participant_id) REFERENCES participants(room_code, id) ON DELETE CASCADE
    )`,
    db`CREATE TABLE IF NOT EXISTS scores (
      room_code TEXT NOT NULL REFERENCES rooms(code) ON DELETE CASCADE,
      participant_id UUID NOT NULL,
      participant_name TEXT NOT NULL,
      round INTEGER NOT NULL CHECK (round BETWEEN 1 AND 3),
      accuracy DOUBLE PRECISION NOT NULL,
      points DOUBLE PRECISION NOT NULL,
      errors INTEGER NOT NULL,
      submitted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (room_code, participant_id, round),
      FOREIGN KEY (room_code, participant_id) REFERENCES participants(room_code, id) ON DELETE CASCADE
    )`,
    db`CREATE TABLE IF NOT EXISTS admin_login_attempts (
      ip TEXT NOT NULL,
      attempted_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
    db`CREATE INDEX IF NOT EXISTS admin_login_attempts_ip_time_idx
      ON admin_login_attempts (ip, attempted_at)`,
    db`CREATE INDEX IF NOT EXISTS rooms_running_ends_at_idx
      ON rooms (ends_at) WHERE status = 'running'`
  ]).then(() => undefined).catch((error: unknown) => {
    schemaReady = undefined;
    throw error;
  });
  await schemaReady;
  return db;
}

function adminSettings(): { password: string; secret: string } {
  const password = process.env.ADMIN_PASSWORD;
  const secret = process.env.ADMIN_TOKEN_SECRET;
  if (!password || password.trim().length < 12 || !secret || secret.length < 32) {
    throw new HttpError(
      503,
      "Organiser sign-in is not configured. Set ADMIN_PASSWORD (12+ characters) and ADMIN_TOKEN_SECRET (32+ characters)."
    );
  }
  return { password, secret };
}

function getBearerToken(request: Request): string | undefined {
  const authorization = request.headers.get("authorization");
  return authorization?.startsWith("Bearer ") ? authorization.slice(7) : undefined;
}

function requireAdmin(request: Request, secret: string): void {
  if (!isValidAdminToken(getBearerToken(request), secret)) {
    throw new HttpError(401, "Organiser sign-in required.");
  }
}

function issueParticipantToken(roomCode: string, participantId: string, secret: string): string {
  const payload = `${roomCode}.${participantId}`;
  const signature = createHmac("sha256", secret).update(`participant:${payload}`).digest("base64url");
  return `${Buffer.from(payload).toString("base64url")}.${signature}`;
}

function isValidParticipantToken(
  token: string | undefined,
  roomCode: string,
  participantId: string,
  secret: string
): boolean {
  if (!token) return false;
  const separator = token.lastIndexOf(".");
  if (separator <= 0) return false;
  const payload = Buffer.from(token.slice(0, separator), "base64url").toString();
  if (payload !== `${roomCode}.${participantId}`) return false;
  const supplied = Buffer.from(token.slice(separator + 1), "base64url");
  const expected = createHmac("sha256", secret).update(`participant:${payload}`).digest();
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

async function readJson(request: Request): Promise<unknown> {
  const contentLength = Number(request.headers.get("content-length") ?? 0);
  if (contentLength > 50_000) throw new HttpError(413, "Request body is too large.");
  try {
    return await request.json();
  } catch {
    throw new HttpError(400, "Request body must be valid JSON.");
  }
}

function roomCodeFromPath(value: string | undefined): string {
  const code = (value ?? "").toUpperCase();
  if (!/^[A-Z0-9]{6}$/.test(code)) throw new HttpError(400, "Invalid room code.");
  return code;
}

async function getRoom(db: NeonClient, code: string): Promise<Row> {
  const rows = await db`SELECT code, name, status, round, remaining_ms, ends_at, created_at
    FROM rooms WHERE code = ${code}`;
  if (!rows[0]) throw new HttpError(404, "Room not found.");
  return rows[0] as Row;
}

async function finalizeRound(db: NeonClient, code: string, room: Row): Promise<void> {
  const round = Number(room.round) as RoundNumber;
  if (room.status !== "finalizing") {
    const claimed = await db`UPDATE rooms SET status = 'finalizing'
      WHERE code = ${code} AND round = ${round} AND status IN ('running', 'paused')
      RETURNING code`;
    if (!claimed.length) return;
  }
  const challengeRows = await db`SELECT reference_text FROM room_challenges
    WHERE room_code = ${code} AND round = ${round}`;
  if (!challengeRows[0]) throw new Error(`Missing reference for room ${code}, round ${round}.`);
  const participants = await db`SELECT p.id::text AS participant_id, p.name, COALESCE(s.text, '') AS text
    FROM participants p
    LEFT JOIN submissions s
      ON s.room_code = p.room_code AND s.participant_id = p.id AND s.round = ${round}
    WHERE p.room_code = ${code}`;
  const nextStatus: RoomStatus = round === 3 ? "completed" : "between_rounds";
  const statements = participants.map((participant) => {
    const result = evaluateSubmission(
      String(participant.text),
      String(challengeRows[0].reference_text),
      ROUND_CONFIG[round].points
    );
    return db`INSERT INTO scores
      (room_code, participant_id, participant_name, round, accuracy, points, errors)
      VALUES (${code}, ${String(participant.participant_id)}, ${String(participant.name)},
        ${round}, ${result.accuracy}, ${result.points}, ${result.errors})
      ON CONFLICT (room_code, participant_id, round) DO UPDATE SET
        participant_name = EXCLUDED.participant_name,
        accuracy = EXCLUDED.accuracy,
        points = EXCLUDED.points,
        errors = EXCLUDED.errors,
        submitted_at = now()`;
  });
  statements.push(
    db`DELETE FROM submissions WHERE room_code = ${code} AND round = ${round}`,
    db`UPDATE rooms SET status = ${nextStatus}, remaining_ms = 0, ends_at = NULL
      WHERE code = ${code} AND round = ${round} AND status = 'finalizing'`
  );
  await db.transaction(statements);
}

async function finalizeExpiredRooms(db: NeonClient): Promise<void> {
  const expired = await db`SELECT code, name, status, round, remaining_ms, ends_at, created_at
    FROM rooms WHERE status = 'finalizing' OR (status = 'running' AND ends_at <= now())`;
  for (const room of expired) await finalizeRound(db, String(room.code), room as Row);
}

async function getRoomState(db: NeonClient, code: string): Promise<Row> {
  let room = await getRoom(db, code);
  if (room.status === "finalizing") {
    await finalizeRound(db, code, room);
    room = await getRoom(db, code);
  } else if (room.status === "running" && room.ends_at && new Date(String(room.ends_at)).getTime() <= Date.now()) {
    await finalizeRound(db, code, room);
    room = await getRoom(db, code);
  }
  const round = Number(room.round) as RoundNumber;
  const [participants, scores, challengeRows] = await Promise.all([
    db`SELECT p.id::text AS id, p.name,
        ROUND(COALESCE(SUM(s.points), 0)::numeric, 2)::float8 AS total_points,
        COUNT(s.round)::int AS rounds_completed
      FROM participants p LEFT JOIN scores s
        ON s.room_code = p.room_code AND s.participant_id = p.id
      WHERE p.room_code = ${code}
      GROUP BY p.id, p.name ORDER BY total_points DESC, p.name`,
    db`SELECT s.participant_id::text AS participant_id, s.participant_name AS name,
        s.round, s.accuracy, s.points, s.errors
      FROM scores s WHERE s.room_code = ${code} ORDER BY s.round`,
    room.status === "lobby"
      ? Promise.resolve([])
      : db`SELECT round, reference_text, duration_seconds FROM room_challenges
          WHERE room_code = ${code} AND round = ${round}`
  ]);
  const endsAt = room.ends_at ? new Date(String(room.ends_at)).getTime() : null;
  const remainingMs = room.status === "running" && endsAt !== null
    ? Math.max(0, endsAt - Date.now())
    : Number(room.remaining_ms);
  const challenge = challengeRows[0];
  return {
    code,
    name: String(room.name),
    status: String(room.status) as RoomStatus,
    round,
    remainingMs,
    serverTime: Date.now(),
    participants: participants.map((person) => ({
      id: String(person.id),
      name: String(person.name),
      totalPoints: Number(person.total_points),
      roundsCompleted: Number(person.rounds_completed)
    })),
    scores: scores.map((score) => ({
      participantId: String(score.participant_id),
      name: String(score.name),
      round: Number(score.round),
      accuracy: Number(score.accuracy),
      points: Number(score.points),
      errors: Number(score.errors)
    })),
    ...(challenge ? {
      challenge: {
        round,
        title: ROUND_CONFIG[round].title,
        duration: Number(challenge.duration_seconds),
        points: ROUND_CONFIG[round].points,
        referenceText: String(challenge.reference_text)
      }
    } : {})
  };
}

async function handleLogin(request: Request, db: NeonClient): Promise<Response> {
  const { password, secret } = adminSettings();
  const parsed = z.object({ password: z.string().min(1).max(200) }).safeParse(await readJson(request));
  if (!parsed.success) throw new HttpError(400, "Enter the organiser password.");
  const ip = (request.headers.get("x-forwarded-for") ?? "unknown").split(",")[0].trim().slice(0, 100);
  await db`DELETE FROM admin_login_attempts WHERE attempted_at < now() - interval '1 day'`;
  const attempts = await db`SELECT COUNT(*)::int AS count FROM admin_login_attempts
    WHERE ip = ${ip} AND attempted_at > now() - interval '15 minutes'`;
  if (Number(attempts[0]?.count ?? 0) >= 10) {
    throw new HttpError(429, "Too many sign-in attempts. Try again in 15 minutes.");
  }
  if (parsed.data.password !== password) {
    await db`INSERT INTO admin_login_attempts (ip) VALUES (${ip})`;
    throw new HttpError(401, "Incorrect organiser password.");
  }
  await db`DELETE FROM admin_login_attempts WHERE ip = ${ip}`;
  return json({ token: issueAdminToken(secret) });
}

async function handleJoin(request: Request, code: string, db: NeonClient): Promise<Response> {
  const parsed = z.object({
    name: z.string().trim().min(1).max(40),
    usn: z.string().trim().min(3).max(32).regex(/^[A-Za-z0-9._/-]+$/)
      .transform((value) => value.toUpperCase()),
    participantId: z.string().uuid().optional()
  }).safeParse(await readJson(request));
  if (!parsed.success) throw new HttpError(400, "Enter a valid display name and USN.");
  await getRoomState(db, code);
  const room = await getRoom(db, code);
  if (room.status === "completed") throw new HttpError(409, "This room is no longer accepting participants.");

  const existing = parsed.data.participantId
    ? await db`SELECT id FROM participants WHERE room_code = ${code} AND id = ${parsed.data.participantId}`
    : [];
  if (!existing[0] && room.status !== "lobby") {
    throw new HttpError(409, "This round is underway. Ask the organiser to add you before it starts.");
  }
  try {
    if (existing[0]) {
      await db`UPDATE participants SET name = ${parsed.data.name}, usn = ${parsed.data.usn}
        WHERE room_code = ${code} AND id = ${parsed.data.participantId}`;
    } else {
      await db`INSERT INTO participants (id, room_code, name, usn)
        VALUES (${randomUUID()}, ${code}, ${parsed.data.name}, ${parsed.data.usn})`;
    }
  } catch (error) {
    if (error instanceof Error && error.message.toLowerCase().includes("unique")) {
      throw new HttpError(409, "That USN is already registered in this room.");
    }
    throw error;
  }
  const participant = existing[0]
    ? String(existing[0].id)
    : String((await db`SELECT id::text AS id FROM participants
        WHERE room_code = ${code} AND usn = ${parsed.data.usn}`)[0]?.id ?? "");
  if (!participant) throw new Error("Participant registration did not return an ID.");
  const { secret } = adminSettings();
  return json({
    participantId: participant,
    participantToken: issueParticipantToken(code, participant, secret),
    state: await getRoomState(db, code)
  });
}

async function handleSubmission(request: Request, code: string, db: NeonClient): Promise<Response> {
  const parsed = z.object({
    participantId: z.string().uuid(),
    text: z.string().max(10_000)
  }).safeParse(await readJson(request));
  if (!parsed.success) throw new HttpError(400, "Invalid participant submission.");
  const { secret } = adminSettings();
  if (!isValidParticipantToken(getBearerToken(request), code, parsed.data.participantId, secret)) {
    throw new HttpError(401, "Participant session is invalid. Rejoin the room.");
  }
  const room = await getRoom(db, code);
  if (room.status !== "running") throw new HttpError(409, "The round is not accepting input.");
  const round = Number(room.round) as RoundNumber;
  const saved = await db`WITH active_room AS (
      SELECT code, round FROM rooms
      WHERE code = ${code} AND status = 'running' AND round = ${round} AND ends_at > now()
      FOR SHARE
    )
    INSERT INTO submissions (room_code, participant_id, round, text)
    SELECT active_room.code, ${parsed.data.participantId}, active_room.round, ${parsed.data.text}
    FROM active_room
    ON CONFLICT (room_code, participant_id, round) DO UPDATE SET
      text = EXCLUDED.text, updated_at = now()
    RETURNING participant_id`;
  if (!saved.length) {
    const latest = await getRoom(db, code);
    if (latest.status === "running" && latest.ends_at && new Date(String(latest.ends_at)).getTime() <= Date.now()) {
      await finalizeRound(db, code, latest);
    }
    throw new HttpError(409, "Time is up. Your input can no longer be changed.");
  }
  return json({ ok: true });
}

async function createRoom(request: Request, db: NeonClient): Promise<Response> {
  const parsed = createRoomSchema.safeParse(await readJson(request));
  if (!parsed.success) throw new HttpError(400, parsed.error.issues[0]?.message ?? "Invalid room details.");
  const challenges = [...parsed.data.challenges].sort((left, right) => left.round - right.round);
  let code = "";
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const candidate = Array.from({ length: 6 }, () => alphabet[randomInt(alphabet.length)]).join("");
    const found = await db`SELECT 1 FROM rooms WHERE code = ${candidate}`;
    if (!found.length) {
      code = candidate;
      break;
    }
  }
  if (!code) throw new HttpError(503, "Unable to allocate a unique room code. Try again.");
  const createdAt = new Date().toISOString();
  await db.transaction([
    db`INSERT INTO rooms (code, name, status, round, remaining_ms)
      VALUES (${code}, ${parsed.data.name}, 'lobby', 1, ${ROUND_CONFIG[1].duration * 1000})`,
    ...challenges.map((challenge) => db`INSERT INTO room_challenges
      (room_code, round, reference_text, duration_seconds)
      VALUES (${code}, ${challenge.round}, ${challenge.referenceText},
        ${challenge.duration ?? ROUND_CONFIG[challenge.round].duration})`)
  ]);
  return json({
    code,
    name: parsed.data.name,
    status: "lobby",
    round: 1,
    participants: 0,
    totalPoints: 0,
    createdAt
  }, 201);
}

async function adminRooms(db: NeonClient): Promise<Response> {
  await finalizeExpiredRooms(db);
  const rooms = await db`SELECT r.code, r.name, r.status, r.round, r.created_at,
      (SELECT COUNT(*)::int FROM participants p WHERE p.room_code = r.code) AS participants,
      (SELECT COALESCE(SUM(s.points), 0)::float8 FROM scores s WHERE s.room_code = r.code) AS total_points
    FROM rooms r ORDER BY r.created_at DESC`;
  return json(rooms.map((room) => ({
    code: String(room.code),
    name: String(room.name),
    status: String(room.status),
    round: Number(room.round),
    participants: Number(room.participants),
    totalPoints: Number(room.total_points),
    createdAt: new Date(String(room.created_at)).toISOString()
  })));
}

async function roomDetails(db: NeonClient, code: string): Promise<Response> {
  const state = await getRoomState(db, code);
  const [challenges, participants, scores] = await Promise.all([
    db`SELECT round, reference_text, duration_seconds FROM room_challenges
      WHERE room_code = ${code} ORDER BY round`,
    db`SELECT id::text AS id, name, usn FROM participants WHERE room_code = ${code} ORDER BY name`,
    db`SELECT s.participant_id::text AS participant_id, s.participant_name, p.usn,
        s.round, s.accuracy, s.points, s.errors
      FROM scores s LEFT JOIN participants p
        ON p.room_code = s.room_code AND p.id = s.participant_id
      WHERE s.room_code = ${code} ORDER BY s.participant_name, s.round`
  ]);
  return json({
    room: {
      code,
      name: state.name,
      status: state.status,
      round: state.round,
      createdAt: new Date(String((await getRoom(db, code)).created_at)).toISOString(),
      participants: participants.length,
      totalPoints: scores.reduce((total, score) => total + Number(score.points), 0)
    },
    challenges: challenges.map((challenge) => ({
      round: Number(challenge.round),
      referenceText: String(challenge.reference_text),
      duration: Number(challenge.duration_seconds)
    })),
    participants: participants.map((person) => ({
      id: String(person.id),
      name: String(person.name),
      usn: String(person.usn)
    })),
    scores: scores.map((score) => ({
      participantId: String(score.participant_id),
      name: String(score.participant_name),
      usn: String(score.usn ?? ""),
      round: Number(score.round),
      accuracy: Number(score.accuracy),
      points: Number(score.points),
      errors: Number(score.errors)
    }))
  });
}

async function roomAction(db: NeonClient, code: string, action: string): Promise<Response> {
  let room = await getRoom(db, code);
  if (room.status === "finalizing") {
    await finalizeRound(db, code, room);
    if (action === "end") return json({ ok: true });
    throw new HttpError(409, "The round is being finalized. Refresh to see the results.");
  }
  if (room.status === "running" && room.ends_at
    && new Date(String(room.ends_at)).getTime() <= Date.now()) {
    await finalizeRound(db, code, room);
    if (action === "end") return json({ ok: true });
    throw new HttpError(409, "The round timer has expired. Refresh to see the results.");
  }
  room = await getRoom(db, code);
  if (action === "end") {
    if (room.status !== "running" && room.status !== "paused") {
      throw new HttpError(409, "Only an active round can be ended.");
    }
    await finalizeRound(db, code, room);
    return json({ ok: true });
  }
  if (action === "pause") {
    if (room.status !== "running" || !room.ends_at) {
      throw new HttpError(409, "Only a running round can be paused.");
    }
    const updated = await db`UPDATE rooms SET status = 'paused',
        remaining_ms = GREATEST(0, FLOOR(EXTRACT(EPOCH FROM (ends_at - now())) * 1000)::bigint),
        ends_at = NULL
      WHERE code = ${code} AND status = 'running' AND ends_at > now()
        AND round = ${Number(room.round)}
      RETURNING remaining_ms`;
    if (!updated.length) {
      const latest = await getRoom(db, code);
      if (latest.status === "running" && latest.ends_at
        && new Date(String(latest.ends_at)).getTime() <= Date.now()) {
        await finalizeRound(db, code, latest);
        return json({ ok: true });
      }
      throw new HttpError(409, "The room changed while pausing. Refresh and try again.");
    }
    if (Number(updated[0].remaining_ms) <= 0) {
      const latest = await getRoom(db, code);
      if (latest.status === "paused") {
        await finalizeRound(db, code, latest);
      }
      return json({ ok: true });
    }
    return json({ ok: true });
  }
  if (action !== "start") throw new HttpError(404, "Unknown room action.");

  const oldStatus = String(room.status);
  let round = Number(room.round) as RoundNumber;
  let remaining = Number(room.remaining_ms);
  if (oldStatus === "paused") {
    if (remaining <= 0) {
      await finalizeRound(db, code, room);
      throw new HttpError(409, "There is no time remaining in this round.");
    }
  } else if (oldStatus === "lobby" || oldStatus === "between_rounds") {
    if (oldStatus === "between_rounds") {
      if (round >= 3) throw new HttpError(409, "All rounds have already finished.");
      round = (round + 1) as RoundNumber;
    }
    const challenge = await db`SELECT duration_seconds FROM room_challenges
      WHERE room_code = ${code} AND round = ${round}`;
    if (!challenge[0]) throw new Error(`Missing challenge for room ${code}, round ${round}.`);
    remaining = Number(challenge[0].duration_seconds) * 1000;
  } else {
    throw new HttpError(409, "This round cannot be started in its current state.");
  }
  const endsAt = new Date(Date.now() + remaining).toISOString();
  const updated = await db`UPDATE rooms SET status = 'running', round = ${round},
      remaining_ms = ${remaining}, ends_at = ${endsAt}
    WHERE code = ${code} AND status = ${oldStatus} AND round = ${Number(room.round)}
    RETURNING code`;
  if (!updated.length) throw new HttpError(409, "The room changed while starting. Refresh and try again.");
  return json({ ok: true });
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

async function handler(request: Request): Promise<Response> {
  try {
    const url = new URL(request.url);
    const route = (url.searchParams.get("route") ?? url.pathname.replace(/^\/api\/?/, ""))
      .replace(/^\/+|\/+$/g, "");
    const parts = route.split("/").filter(Boolean);
    const method = request.method.toUpperCase();

    if (method === "GET" && parts[0] === "health") return json({ status: "ok" });
    if (method === "GET" && parts[0] === "challenges") {
      return json(CHALLENGE_SEEDS.map((challenge) => ({
        round: challenge.round,
        referenceText: challenge.referenceText
      })));
    }

    const db = await ensureSchema();
    if (method === "POST" && parts[0] === "admin" && parts[1] === "login") {
      return await handleLogin(request, db);
    }
    const { secret } = adminSettings();
    if (parts[0] === "admin") requireAdmin(request, secret);
    if (method === "GET" && parts[0] === "admin" && parts[1] === "rooms" && parts.length === 2) {
      return await adminRooms(db);
    }
    if (method === "POST" && parts[0] === "admin" && parts[1] === "rooms" && parts.length === 2) {
      return await createRoom(request, db);
    }
    if (parts[0] === "admin" && parts[1] === "rooms" && parts[2]) {
      const code = roomCodeFromPath(parts[2]);
      if (method === "GET" && parts.length === 3) return await roomDetails(db, code);
      if (method === "GET" && parts[3] === "scores") {
        const detail = await roomDetails(db, code);
        const payload = await detail.json() as { scores: unknown[] };
        return json(payload.scores);
      }
      if (method === "POST" && parts.length === 4) return await roomAction(db, code, parts[3]);
      if (method === "PATCH" && parts.length === 3) {
        const parsed = z.object({ name: z.string().trim().min(2).max(60) }).safeParse(await readJson(request));
        if (!parsed.success) throw new HttpError(400, parsed.error.issues[0]?.message ?? "Invalid event name.");
        const updated = await db`UPDATE rooms SET name = ${parsed.data.name}
          WHERE code = ${code} AND status = 'completed' RETURNING code`;
        if (!updated.length) throw new HttpError(409, "Only completed events can be renamed.");
        return json({ ok: true, name: parsed.data.name });
      }
      if (method === "DELETE" && parts.length === 3) {
        const deleted = await db`DELETE FROM rooms WHERE code = ${code} AND status = 'completed' RETURNING code`;
        if (!deleted.length) throw new HttpError(409, "Only completed events can be deleted.");
        return json({ ok: true });
      }
    }

    if (parts[0] === "rooms" && parts[1]) {
      const code = roomCodeFromPath(parts[1]);
      if (method === "POST" && parts[2] === "join") return await handleJoin(request, code, db);
      if (method === "GET" && parts[2] === "state") return json(await getRoomState(db, code));
      if (method === "POST" && parts[2] === "submission") return await handleSubmission(request, code, db);
    }
    throw new HttpError(404, "API route not found.");
  } catch (error) {
    if (error instanceof HttpError) return json({ error: error.message }, error.status);
    console.error("Vercel API request failed:", error);
    return json({ error: "Unexpected server error." }, 500);
  }
}

export default { fetch: handler };
