/**
 * mixify-realtime — serveur WebSocket temps réel (salaud par compte).
 *
 * Vercel (serverless) ne peut pas tenir de connexions persistantes : ce petit
 * processus Node les tient, survole les snapshots Forge (playback, login QR,
 * notifications, abonnement) et pousse les changements aux appareils connectés.
 * Les clients gardent le long-poll en plan B si ce serveur est injoignable.
 *
 * Auth : JWT HS256 identique au backend (même JWT_SECRET) OU `pollToken`
 * seul pour le canal login (navigateur non connecté, comme le long-poll).
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";

import { WebSocketServer } from "ws";

const PORT = Number(process.env.PORT || 8080);
const FORGE_API_URL = process.env.FORGE_API_URL;
const FORGE_API_KEY = process.env.FORGE_API_KEY;
const FORGE_PROJECT = process.env.FORGE_PROJECT;
const JWT_SECRET = process.env.JWT_SECRET;

if (!FORGE_API_URL || !FORGE_API_KEY || !FORGE_PROJECT || !JWT_SECRET) {
  console.error("FORGE_API_URL, FORGE_API_KEY, FORGE_PROJECT et JWT_SECRET requis.");
  process.exit(1);
}

function base64url(input) {
  return Buffer.from(input).toString("base64url");
}

/** Vérifie un JWT HS256 du backend, sans dépendance. */
function verifyToken(token) {
  try {
    const [head, body, signature] = token.split(".");
    if (!head || !body || !signature) return null;
    const expected = createHmac("sha256", JWT_SECRET).update(`${head}.${body}`).digest("base64url");
    const given = Buffer.from(signature);
    const want = Buffer.from(expected);
    if (given.length !== want.length || !timingSafeEqual(given, want)) return null;
    const payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
    if (payload.typ !== "session" || typeof payload.userId !== "string") return null;
    if (typeof payload.exp !== "number" || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload.userId;
  } catch {
    return null;
  }
}

async function forgeList(table) {
  const url = `${FORGE_API_URL}/api/public/v1/${FORGE_PROJECT}/${table}?limit=200&offset=0`;
  const response = await fetch(url, {
    headers: { "x-api-key": FORGE_API_KEY, "Content-Type": "application/json" },
  });
  if (!response.ok) return [];
  const payload = await response.json();
  const rows = Array.isArray(payload) ? payload : payload?.data || [];
  return rows.map((row) => (row.data && typeof row.data === "object" ? { ...row.data, ...row } : row));
}

async function forgeGet(table, id) {
  const url = `${FORGE_API_URL}/api/public/v1/${FORGE_PROJECT}/${table}/${id}`;
  const response = await fetch(url, {
    headers: { "x-api-key": FORGE_API_KEY, "Content-Type": "application/json" },
  });
  if (!response.ok) return null;
  const payload = await response.json();
  const record = payload?.data || payload;
  return record?.data ? { ...record.data, ...record } : record;
}

function playbackOf(user) {
  const session = user?.playback ?? null;
  const fresh = session?.updatedAt && Date.now() - Date.parse(session.updatedAt) < 30_000 ? session : null;
  return fresh ?? null;
}

async function snapshot(userId, watches) {
  const data = {};
  if (watches.channels.has("playback") || watches.channels.has("notifications")) {
    const user = await forgeGet("users", userId).catch(() => null);
    if (watches.channels.has("playback")) data.playback = playbackOf(user);
    if (watches.channels.has("notifications")) {
      const rows = await forgeList("notifications").catch(() => []);
      data.notifications = rows.filter((row) => row.user_id === userId && !row.read_at).length;
    }
  }
  if (watches.loginToken) {
    const rows = await forgeList("pairing_codes").catch(() => []);
    const record = rows.find((row) => row.poll_token === watches.loginToken);
    if (!record) data.login = "expired";
    else if (record.status === "pending") {
      data.login = record.expires_at && Date.parse(record.expires_at) < Date.now() ? "expired" : "pending";
    } else data.login = record.status === "confirmed" ? "confirmed" : "expired";
  }
  if (watches.orderId) {
    const row = await forgeGet("subscriptions", watches.orderId).catch(() => null);
    data.subscription = typeof row?.status === "string" ? row.status : null;
  }
  return data;
}

const rooms = new Map();
const keyOf = (data) => JSON.stringify(data);

/** Salaud d'un identité : userId, ou `anon:<pollToken>` pour la connexion QR. */
function roomKey(identity) {
  return identity;
}

function push(room, changed, data) {
  const message = JSON.stringify({ changed, data });
  for (const client of room.clients) {
    if (client.readyState === 1) client.send(message);
  }
}

async function tickRoom(key, room) {
  const data = await snapshot(room.userId, room.watches).catch(() => null);
  if (!data) return;
  const nextKey = keyOf(data);
  if (nextKey !== room.lastKey) {
    const previous = room.lastData || {};
    const changed = [];
    for (const channel of Object.keys(data)) {
      if (JSON.stringify(data[channel]) !== JSON.stringify(previous[channel])) changed.push(channel);
    }
    room.lastKey = nextKey;
    room.lastData = data;
    if (changed.length > 0) push(room, changed, data);
  }
}

const server = createServer((request, response) => {
  if (request.url === "/health") {
    response.writeHead(200, { "Content-Type": "application/json" });
    response.end('{"ok":true}');
    return;
  }
  response.writeHead(404);
  response.end();
});

const wss = new WebSocketServer({ server });

wss.on("connection", (socket, request) => {
  const url = new URL(request.url, "http://localhost");
  const token = url.searchParams.get("token") ?? "";
  const loginToken = url.searchParams.get("pollToken") ?? "";
  const userId = verifyToken(token);
  const anonymousLogin = !userId && Boolean(loginToken);

  if (!userId && !anonymousLogin) {
    socket.close(1008, "Authentification requise");
    return;
  }

  const key = roomKey(userId ? `user:${userId}` : `anon:${loginToken}`);
  let room = rooms.get(key);
  if (!room) {
    room = { userId: userId ?? null, clients: new Set(), watches: { channels: new Set(), loginToken: null, orderId: null }, lastKey: null, lastData: null };
    rooms.set(key, room);
  }
  room.clients.add(socket);

  socket.isAlive = true;
  socket.on("pong", () => {
    socket.isAlive = true;
  });

  socket.on("message", (raw) => {
    let message;
    try {
      message = JSON.parse(raw.toString());
    } catch {
      return;
    }
    if (message.type === "subscribe" && Array.isArray(message.channels)) {
      room.watches.channels = new Set(message.channels);
      return;
    }
    if (message.type === "login_watch" && typeof message.pollToken === "string") {
      room.watches.loginToken = message.pollToken;
      room.watches.channels.add("login");
      return;
    }
    if (message.type === "subscription_watch" && typeof message.orderId === "string") {
      room.watches.orderId = message.orderId;
      room.watches.channels.add("subscription");
      return;
    }
    if (message.type === "ping") socket.send(JSON.stringify({ type: "pong" }));
  });

  socket.on("close", () => {
    room.clients.delete(socket);
    if (room.clients.size === 0) rooms.delete(key);
  });
  socket.on("error", () => socket.terminate());
});

// Un seul lecteur central : chaque salle est survolée toutes les 2 s.
setInterval(() => {
  for (const [key, room] of rooms) {
    if (room.clients.size > 0) void tickRoom(key, room);
  }
}, 2_000);

// Détecte les sockets morts (fly ne replonge pas les connexions fantômes).
setInterval(() => {
  for (const client of wss.clients) {
    if (client.isAlive === false) {
      client.terminate();
      continue;
    }
    client.isAlive = false;
    client.ping();
  }
}, 30_000);

server.listen(PORT, () => console.log(`mixify-realtime sur :${PORT}`));
