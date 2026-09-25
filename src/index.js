const PASSWORD_ITERATIONS = 600000;
const SESSION_LIFETIME = 7 * 24 * 60 * 60 * 1000;
const INVITE_LIFETIME = 30 * 60 * 1000;
const RATE_WINDOW = 15 * 60 * 1000;
const encoder = new TextEncoder();

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64Url(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(base64), (character) => character.charCodeAt(0));
}

function randomToken(size = 32) {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(size)));
}

async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: fromBase64Url(salt), iterations: PASSWORD_ITERATIONS, hash: "SHA-256" },
    key,
    256
  );
  return toBase64Url(new Uint8Array(bits));
}

function createInviteCode() {
  const randomWords = crypto.getRandomValues(new Uint32Array(2));
  const randomNumber = BigInt(randomWords[0]) * 4294967296n + BigInt(randomWords[1]);
  return String(100000000000n + (randomNumber % 900000000000n));
}

function jsonResponse(request, body, status = 200) {
  const origin = request.headers.get("Origin") || "*";
   return new Response(status === 204 ? null : JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": origin,
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Authorization, Content-Type",
      "Vary": "Origin",
      "Cache-Control": "no-store"
    }
  });
}

// A single SQLite-backed Durable Object keeps this deliberately small service
// simple while separating account, invite, and per-chat records.
export class ChatRoom {
  constructor(state, env) {
    this.state = state;
    this.sessions = new Set();
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return jsonResponse(request, {}, 204);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await this.handleApi(request, url);
      } catch {
        return jsonResponse(request, { error: "Request could not be completed." }, 500);
      }
    }

    if (url.pathname !== "/ws" || request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return jsonResponse(request, { error: "Not found." }, 404);
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.handleSession(server, url.searchParams.get("chat"));
    return new Response(null, { status: 101, webSocket: client });
  }

  async handleApi(request, url) {
    const path = url.pathname;
    if (path === "/api/register" && request.method === "POST") return this.register(request);
    if (path === "/api/login" && request.method === "POST") return this.login(request);

    const username = await this.authenticate(request);
    if (!username) return jsonResponse(request, { error: "Please sign in again." }, 401);

    if (path === "/api/session" && request.method === "GET") {
      return jsonResponse(request, { username });
    }

    if (path === "/api/logout" && request.method === "POST") {
      const token = this.getToken(request);
      const tokenHash = await sha256(token);
      await this.state.storage.delete(`session:${tokenHash}`);
      for (const session of this.sessions) {
        if (session.tokenHash === tokenHash) {
          this.sessions.delete(session);
          try { session.ws.close(1008, "Signed out"); } catch { }
        }
      }
      return jsonResponse(request, { ok: true });
    }

    if (path === "/api/chats" && request.method === "GET") {
      const records = await this.state.storage.list({ prefix: "chat:" });
      const chats = [...records.values()]
        .filter((chat) => chat.members.includes(username))
        .map((chat) => ({ id: chat.id, members: chat.members, updatedAt: chat.updatedAt || chat.createdAt }));
      chats.sort((first, second) => second.updatedAt - first.updatedAt);
      return jsonResponse(request, { chats });
    }

    if (path === "/api/chats" && request.method === "POST") return this.createChat(request, username);
    if (path === "/api/chats/join" && request.method === "POST") return this.joinChat(request, username);
    const inviteMatch = path.match(/^\/api\/chats\/([a-f0-9-]+)\/invite$/);
    if (inviteMatch && request.method === "POST") return this.issueInvite(request, username, inviteMatch[1]);
    return jsonResponse(request, { error: "Not found." }, 404);
  }

  async readBody(request) {
    try {
      const body = await request.json();
      return body && typeof body === "object" && !Array.isArray(body) ? body : null;
    } catch {
      return null;
    }
  }

  async consumeRateLimit(key, limit) {
    const now = Date.now();
    return this.state.storage.transaction(async (transaction) => {
      const current = await transaction.get(`rate:${key}`);
      const entry = current && current.until > now ? current : { count: 0, until: now + RATE_WINDOW };
      if (entry.count >= limit) return false;
      entry.count += 1;
      await transaction.put(`rate:${key}`, entry);
      return true;
    });
  }

  rateKey(request) {
    return request.headers.get("CF-Connecting-IP") || "unknown";
  }

  async register(request) {
    const body = await this.readBody(request);
    const username = typeof body?.username === "string" ? body.username.trim().toLowerCase() : "";
    const password = typeof body?.password === "string" ? body.password : "";
    if (!/^[a-z0-9_]{3,24}$/.test(username) || password.length < 10 || password.length > 128) {
      return jsonResponse(request, { error: "Use a 3-24 character username and a 10-128 character password." }, 400);
    }
    if (!await this.consumeRateLimit(`auth:${this.rateKey(request)}`, 10)) {
      return jsonResponse(request, { error: "Too many attempts. Try again in 15 minutes." }, 429);
    }

    const salt = randomToken(16);
    const passwordHash = await hashPassword(password, salt);
    const created = await this.state.storage.transaction(async (transaction) => {
      const key = `user:${username}`;
      if (await transaction.get(key)) return false;
      await transaction.put(key, { username, salt, passwordHash, createdAt: Date.now() });
      return true;
    });
    if (!created) return jsonResponse(request, { error: "That username is unavailable." }, 409);
    return this.createSession(request, username);
  }

  async login(request) {
    const body = await this.readBody(request);
    const username = typeof body?.username === "string" ? body.username.trim().toLowerCase() : "";
    const password = typeof body?.password === "string" ? body.password : "";
    if (!username || password.length > 128) return jsonResponse(request, { error: "Username or password is incorrect." }, 401);
    if (!await this.consumeRateLimit(`auth:${this.rateKey(request)}`, 10)) {
      return jsonResponse(request, { error: "Too many attempts. Try again in 15 minutes." }, 429);
    }

    const user = await this.state.storage.get(`user:${username}`);
    const salt = user?.salt || "AAAAAAAAAAAAAAAAAAAAAA";
    const attemptedHash = await hashPassword(password, salt);
    if (!user || attemptedHash !== user.passwordHash) {
      return jsonResponse(request, { error: "Username or password is incorrect." }, 401);
    }
    return this.createSession(request, username);
  }

  async createSession(request, username) {
    const token = randomToken();
    const tokenHash = await sha256(token);
    const expiresAt = Date.now() + SESSION_LIFETIME;
    await this.state.storage.put(`session:${tokenHash}`, { username, expiresAt });
    return jsonResponse(request, { token, username, expiresAt });
  }

  getToken(request) {
    const authorization = request.headers.get("Authorization") || "";
    return authorization.startsWith("Bearer ") ? authorization.slice(7) : "";
  }

  async authenticate(request) {
    const token = this.getToken(request);
    if (!token) return null;
    const sessionKey = `session:${await sha256(token)}`;
    const session = await this.state.storage.get(sessionKey);
    if (!session || session.expiresAt <= Date.now()) {
      if (session) await this.state.storage.delete(sessionKey);
      return null;
    }
    return session.username;
  }

  async createChat(request, username) {
    const id = crypto.randomUUID();
    const inviteCode = createInviteCode();
    const inviteHash = await sha256(inviteCode);
    const now = Date.now();
    const expiresAt = now + INVITE_LIFETIME;
    const chat = { id, members: [username], createdAt: now, updatedAt: now, inviteHash, inviteExpiresAt: expiresAt };
    await this.state.storage.transaction(async (transaction) => {
      await transaction.put(`chat:${id}`, chat);
      await transaction.put(`invite:${inviteHash}`, { chatId: id, expiresAt });
    });
    return jsonResponse(request, { chat, inviteCode, expiresAt }, 201);
  }

  async issueInvite(request, username, chatId) {
    const inviteCode = createInviteCode();
    const inviteHash = await sha256(inviteCode);
    const expiresAt = Date.now() + INVITE_LIFETIME;
    const result = await this.state.storage.transaction(async (transaction) => {
      const chatKey = `chat:${chatId}`;
      const chat = await transaction.get(chatKey);
      if (!chat || !chat.members.includes(username) || chat.members.length >= 2) return null;
      if (chat.inviteHash) await transaction.delete(`invite:${chat.inviteHash}`);
      chat.inviteHash = inviteHash;
      chat.inviteExpiresAt = expiresAt;
      await transaction.put(chatKey, chat);
      await transaction.put(`invite:${inviteHash}`, { chatId, expiresAt });
      return chat;
    });
    if (!result) return jsonResponse(request, { error: "You cannot create an invite for this chat." }, 403);
    return jsonResponse(request, { inviteCode, expiresAt });
  }

  async joinChat(request, username) {
    const body = await this.readBody(request);
    const inviteCode = typeof body?.code === "string" ? body.code.trim() : "";
    if (!/^\d{12}$/.test(inviteCode)) return jsonResponse(request, { error: "Invite number is invalid or expired." }, 400);
    if (!await this.consumeRateLimit(`invite:${username}`, 12)) {
      return jsonResponse(request, { error: "Too many invite attempts. Try again in 15 minutes." }, 429);
    }

    const inviteHash = await sha256(inviteCode);
    const result = await this.state.storage.transaction(async (transaction) => {
      const inviteKey = `invite:${inviteHash}`;
      const invite = await transaction.get(inviteKey);
      if (!invite || invite.expiresAt <= Date.now()) return null;
      const chatKey = `chat:${invite.chatId}`;
      const chat = await transaction.get(chatKey);
      if (!chat || chat.members.length >= 2 && !chat.members.includes(username)) return null;
      if (chat.members.includes(username)) return { chat, added: false };
      chat.members.push(username);
      chat.updatedAt = Date.now();
      delete chat.inviteHash;
      delete chat.inviteExpiresAt;
      await transaction.put(chatKey, chat);
      await transaction.delete(inviteKey);
      return { chat, added: true };
    });
    if (!result) return jsonResponse(request, { error: "Invite number is invalid or expired." }, 400);
    if (result.added) {
      const payload = JSON.stringify({ type: "chat_updated", chat: result.chat });
      for (const session of this.sessions) {
        if (session.chatId === result.chat.id && session.ws.readyState === 1) {
          try { session.ws.send(payload); } catch { this.sessions.delete(session); }
        }
      }
    }
    return jsonResponse(request, { chat: result.chat });
  }

  handleSession(ws, chatId) {
    ws.accept();
    let session = null;
    const authTimeout = setTimeout(() => {
      if (!session) ws.close(1008, "Sign in required");
    }, 10000);

    ws.addEventListener("message", async (event) => {
      let data;
      try { data = JSON.parse(event.data); } catch { return; }
      if (!session) {
        if (data.type !== "auth" || typeof data.token !== "string" || !chatId) {
          ws.close(1008, "Sign in required");
          return;
        }
        const tokenHash = await sha256(data.token);
        const storedSession = await this.state.storage.get(`session:${tokenHash}`);
        const chat = await this.state.storage.get(`chat:${chatId}`);
        if (!storedSession || storedSession.expiresAt <= Date.now() || !chat?.members.includes(storedSession.username)) {
          ws.close(1008, "Not allowed in this chat");
          return;
        }
        clearTimeout(authTimeout);
        session = { ws, chatId, username: storedSession.username, tokenHash, expiresAt: storedSession.expiresAt };
        this.sessions.add(session);
        const messages = (await this.state.storage.get(`messages:${chatId}`)) || [];
        ws.send(JSON.stringify({ type: "ready", messages }));
        return;
      }
      if (session.expiresAt <= Date.now()) {
        this.sessions.delete(session);
        ws.close(1008, "Session expired");
        return;
      }
      if (data.type !== "chat" || typeof data.text !== "string" || data.text.length > 6000) return;

      const entry = { sender: session.username, text: data.text, ts: Date.now() };

      const messageKey = `messages:${session.chatId}`;
      await this.state.storage.transaction(async (transaction) => {
        const list = (await transaction.get(messageKey)) || [];
        list.push(entry);
        if (list.length > 500) list.shift();
        await transaction.put(messageKey, list);
        const chat = await transaction.get(`chat:${session.chatId}`);
        if (chat) {
          chat.updatedAt = entry.ts;
          await transaction.put(`chat:${session.chatId}`, chat);
        }
      });

      const payload = JSON.stringify({ type: "chat", message: entry });
      for (const recipient of this.sessions) {
        if (recipient.chatId !== session.chatId) continue;
        if (recipient.ws.readyState !== 1) {
          this.sessions.delete(recipient);
          continue;
        }
        try { recipient.ws.send(payload); } catch { this.sessions.delete(recipient); }
      }
    });

    ws.addEventListener("close", () => {
      clearTimeout(authTimeout);
      if (session) this.sessions.delete(session);
    });
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/ws" || url.pathname.startsWith("/api/")) {
      const id = env.CHATROOM.idFromName("duochat-control");
      const stub = env.CHATROOM.get(id);
      return stub.fetch(request);
    }
    return new Response("DuoChat worker is running.", { status: 200 });
  }
};
