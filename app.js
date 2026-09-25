import "./styles.css";
import {
  auth,
  googleProvider,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  fbSignOut,
  onAuthStateChanged,
  getUserProfile,
  claimUsername,
  recordChatOpened,
  subscribeToChatReads,
  recordUserTyping,
  subscribeToChatTyping,
  getAllRegisteredUsers,
  sendDirectChatRequest,
  subscribeToIncomingRequests,
  acceptDirectChatRequest,
  declineDirectChatRequest,
  savePersistentChatKey,
  getPersistentChatKey,
  saveFirestoreChat,
  subscribeToUserChats,
  saveFirestoreMessage,
  subscribeToChatMessages,
  deleteFirestoreChat
} from "./src/firebase.js";

const WORKER_URL = "wss://duochat-worker.dwagszone.workers.dev/ws";
const API_BASE = WORKER_URL.replace(/^wss:/, "https:").replace(/\/ws$/, "");
const CHAT_KEY_PREFIX = "duochat:key:";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const elements = (id) => document.getElementById(id);

let currentUser = null;
let username = "";
let token = "";
let authMode = "login"; // 'login' or 'register'
let chats = [];
let pendingRequests = [];
let activeInboxTab = "messages"; // "messages" or "requests"
let activeChatId = "";
let socket = null;
let reconnectTimer = 0;
let toastTimer = 0;
let renderedMessages = new Set();
let currentChatReads = {};
let unsubscribeChatReads = null;
let unsubscribeChatTyping = null;
let unsubscribeRequests = null;
let partnerTypingTimeout = null;
let typingStopTimeout = null;
let lastTypingSentAt = 0;
let isCurrentlyTyping = false;
let registeredUsers = [];

// Robust, padding-safe Base64URL encoding/decoding
function bytesToBase64Url(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = "";
  const len = u8.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(u8[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
  if (!value || typeof value !== "string") throw new Error("Invalid base64 string");
  let base64 = value.trim().replace(/-/g, "+").replace(/_/g, "/");
  const pad = base64.length % 4;
  if (pad) {
    base64 += "=".repeat(4 - pad);
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function generateChatKey() {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  return bytesToBase64Url(rawKey);
}

async function importChatKey(encodedKey) {
  if (!encodedKey) throw new Error("Missing encryption key");
  const bytes = base64UrlToBytes(encodedKey.trim());
  if (bytes.length !== 32) throw new Error("That encryption key does not look right.");
  return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

function saveChatKey(chatId, key) {
  localStorage.setItem(`${CHAT_KEY_PREFIX}${chatId}`, key);
  if (currentUser) {
    savePersistentChatKey(chatId, currentUser.uid, key);
  }
}

async function getOrFetchChatKey(chatId) {
  let key = localStorage.getItem(`${CHAT_KEY_PREFIX}${chatId}`);
  if (key) return key;
  if (currentUser) {
    key = await getPersistentChatKey(chatId, currentUser.uid);
    if (key) {
      localStorage.setItem(`${CHAT_KEY_PREFIX}${chatId}`, key);
      return key;
    }
  }
  return "";
}

async function encryptMessage(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoder.encode(text));
  return JSON.stringify({ iv: bytesToBase64Url(iv), ct: bytesToBase64Url(ciphertext) });
}

async function decryptMessage(key, payload) {
  try {
    const encrypted = typeof payload === "string" ? JSON.parse(payload) : payload;
    if (encrypted && encrypted.iv && encrypted.ct) {
      const plaintext = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: base64UrlToBytes(encrypted.iv) },
        key,
        base64UrlToBytes(encrypted.ct)
      );
      return decoder.decode(plaintext);
    }
  } catch (err) {
    console.warn("Decryption error:", err);
  }
  if (typeof payload === "string" && !payload.startsWith('{"iv":')) {
    return payload;
  }
  throw new Error("Message could not be decrypted.");
}

// Synchronize worker session with Firebase auth user
async function syncWorkerSession(user, claimedUsername) {
  try {
    const workerPassword = `firebase_${user.uid}_duochat`;
    let res;
    try {
      res = await fetch(`${API_BASE}/api/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: claimedUsername, password: workerPassword }),
        cache: "no-store"
      });
    } catch {
      // Offline fallback
    }

    if (!res || !res.ok) {
      const regRes = await fetch(`${API_BASE}/api/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: claimedUsername, password: workerPassword }),
        cache: "no-store"
      });
      if (regRes.ok) {
        const data = await regRes.json();
        return data.token;
      }
    } else {
      const data = await res.json();
      return data.token;
    }
  } catch (err) {
    console.warn("Could not sync worker token:", err);
  }
  return user.uid;
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Content-Type", "application/json");
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let response;
  try {
    response = await fetch(`${API_BASE}${path}`, { ...options, headers, cache: "no-store" });
  } catch {
    throw new Error("Can't reach DuoChat right now. Check your connection and try again.");
  }
  const contentType = response.headers.get("Content-Type") || "";
  if (!contentType.includes("application/json")) {
    throw new Error("DuoChat's server needs an update before it can handle this request.");
  }
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || "The request could not be completed.");
  return result;
}

function showAuthMode(mode) {
  authMode = mode;
  const registering = mode === "register";
  elements("authTitle").innerHTML = registering ? "Make this space yours." : "Good conversations<br>start here.";
  elements("authDescription").textContent = registering
    ? "Create a secure account with your email and custom handle."
    : "Sign in to get back to your space. Just you, your person, and the conversation.";
  elements("authSubmit").textContent = registering ? "Create my account" : "Sign in";
  elements("authSwitch").textContent = registering ? "Already have an account? Sign in" : "New here? Create an account";
  elements("usernameGroup").hidden = !registering;
  elements("passwordInput").autocomplete = registering ? "new-password" : "current-password";
  elements("passwordHint").hidden = !registering;
  elements("authError").textContent = "";
}

async function handleUserAuthenticated(user) {
  currentUser = user;
  
  let profile = await getUserProfile(user.uid);
  if (!profile || !profile.username) {
    let proposedHandle = "";
    if (user.displayName) {
      proposedHandle = user.displayName.toLowerCase().replace(/[^a-z0-9_]/g, "").slice(0, 20);
    }
    if (!proposedHandle || proposedHandle.length < 3) {
      if (user.email) {
        proposedHandle = user.email.split("@")[0].toLowerCase().replace(/[^a-z0-9_]/g, "").slice(0, 20);
      }
    }
    // Attempt auto-claiming handle so user can start chatting immediately
    if (proposedHandle && proposedHandle.length >= 3) {
      try {
        profile = await claimUsername(user.uid, proposedHandle, user.email || "");
      } catch (e) {
        console.log("Could not auto-claim handle, asking user:", e);
      }
    }

    if (!profile || !profile.username) {
      if (proposedHandle) {
        elements("handleModalInput").value = proposedHandle;
      }
      elements("handleError").textContent = "";
      elements("handleModal").showModal();
      return;
    }
  }

  username = profile.username;
  token = await syncWorkerSession(user, username);

  elements("whoami").textContent = `@${username}`;
  elements("userEmailTag").textContent = user.email || user.displayName || `@${username}`;
  elements("signinScreen").hidden = true;
  elements("chatApp").hidden = false;

  await loadChats();
  listenToIncomingRequests();
}

let unsubscribeFirestoreChats = null;

async function loadChats() {
  try {
    const result = await api("/api/chats");
    chats = result.chats || [];
    renderChats();
  } catch (err) {
    console.warn("Could not load chats from worker:", err);
    chats = [];
    renderChats();
  }

  // Also subscribe to Firestore chats for persistent sync
  if (unsubscribeFirestoreChats) {
    unsubscribeFirestoreChats();
    unsubscribeFirestoreChats = null;
  }
  if (username) {
    unsubscribeFirestoreChats = subscribeToUserChats(username, (fsChats) => {
      for (const fc of fsChats) {
        if (!chats.some((c) => c.id === fc.id)) {
          chats.unshift(fc);
        }
      }
      renderChats();
    });
  }
}

function listenToIncomingRequests() {
  if (unsubscribeRequests) {
    unsubscribeRequests();
    unsubscribeRequests = null;
  }
  if (!currentUser) return;
  unsubscribeRequests = subscribeToIncomingRequests(currentUser.uid, (requests) => {
    pendingRequests = requests;
    renderRequests();
  });
}

function switchInboxTab(tab) {
  activeInboxTab = tab;
  const isMessages = tab === "messages";
  elements("tabMessages").classList.toggle("active", isMessages);
  elements("tabMessages").setAttribute("aria-selected", String(isMessages));
  elements("tabRequests").classList.toggle("active", !isMessages);
  elements("tabRequests").setAttribute("aria-selected", String(!isMessages));
  elements("messagesPane").hidden = !isMessages;
  elements("requestsPane").hidden = isMessages;
}

function renderRequests() {
  const list = elements("requestsList");
  const badge = elements("requestsBadge");
  const count = pendingRequests.length;
  
  if (count > 0) {
    badge.textContent = String(count);
    badge.hidden = false;
  } else {
    badge.hidden = true;
  }

  list.replaceChildren();
  if (count === 0) {
    const empty = document.createElement("div");
    empty.className = "list-empty";
    empty.textContent = "No message requests. You're all caught up.";
    list.append(empty);
    return;
  }

  for (const req of pendingRequests) {
    const card = document.createElement("article");
    card.className = "request-card";

    const head = document.createElement("div");
    head.className = "request-card-head";

    const avatar = document.createElement("span");
    avatar.className = "avatar";
    avatar.textContent = req.senderUsername.slice(0, 1).toUpperCase();

    const copy = document.createElement("div");
    copy.className = "request-copy";
    const name = document.createElement("strong");
    name.textContent = `@${req.senderUsername}`;
    const desc = document.createElement("small");
    desc.textContent = "Sent you a private chat request";
    copy.append(name, desc);
    head.append(avatar, copy);

    const actions = document.createElement("div");
    actions.className = "request-actions";

    const acceptBtn = document.createElement("button");
    acceptBtn.type = "button";
    acceptBtn.className = "primary";
    acceptBtn.textContent = "Accept";
    acceptBtn.addEventListener("click", () => handleAcceptRequest(req));

    const declineBtn = document.createElement("button");
    declineBtn.type = "button";
    declineBtn.className = "secondary";
    declineBtn.textContent = "Decline";
    declineBtn.addEventListener("click", () => handleDeclineRequest(req));

    actions.append(acceptBtn, declineBtn);
    card.append(head, actions);
    list.append(card);
  }
}

async function handleAcceptRequest(req) {
  try {
    await acceptDirectChatRequest(req, currentUser.uid);
    saveChatKey(req.chatId, req.chatKey);

    let chat = chats.find((c) => c.id === req.chatId);
    if (!chat) {
      chat = {
        id: req.chatId,
        members: [username, req.senderUsername],
        createdAt: req.createdAt
      };
      upsertChat(chat);
    }

    switchInboxTab("messages");
    selectChat(req.chatId);
    showToast(`Accepted request from @${req.senderUsername}`);
  } catch (err) {
    showToast(err.message || "Could not accept request.");
  }
}

async function handleDeclineRequest(req) {
  try {
    await declineDirectChatRequest(req.id);
    showToast(`Declined request from @${req.senderUsername}`);
  } catch (err) {
    showToast("Could not decline request.");
  }
}

function memberSignature(chat) {
  return [...(chat.members || [])].sort().join("|");
}

function renderChats() {
  const list = elements("chatList");
  const filter = elements("chatSearch").value.trim().toLowerCase();
  const visibleChats = chats.filter((chat) => 
    chat.members.some((member) => member !== username && member.toLowerCase().includes(filter)) || 
    (!filter && chat.members.length === 1)
  );

  elements("chatCount").textContent = String(chats.length);
  list.replaceChildren();

  if (!visibleChats.length) {
    const empty = document.createElement("div");
    empty.className = "list-empty";
    empty.textContent = filter ? "No match found." : "No messages yet. Send a message to start chatting.";
    list.append(empty);
    return;
  }

  for (const chat of visibleChats) {
    const other = chat.members.find((member) => member !== username) || "Waiting for partner";
    const row = document.createElement("button");
    row.type = "button";
    row.className = `conversation-row${chat.id === activeChatId ? " selected" : ""}`;

    const avatar = document.createElement("span");
    avatar.className = "avatar";
    avatar.textContent = other === "Waiting for partner" ? "?" : other.slice(0, 1).toUpperCase();

    const copy = document.createElement("span");
    copy.className = "conversation-copy";
    const name = document.createElement("strong");
    name.textContent = `@${other}`;
    const subline = document.createElement("small");
    subline.textContent = chat.members.length === 1 ? "Waiting for response" : "End-to-end encrypted";
    copy.append(name, subline);

    row.append(avatar, copy);
    row.addEventListener("click", () => selectChat(chat.id));
    list.append(row);
  }
}

function upsertChat(chat) {
  const signature = memberSignature(chat);
  chats = chats.filter((existing) => existing.id !== chat.id && !(chat.members.length === 2 && memberSignature(existing) === signature));
  chats.unshift(chat);
  renderChats();
}

function updateChatHeader(chatId) {
  const chat = chats.find((item) => item.id === chatId);
  if (!chat) return;
  const other = chat.members.find((member) => member !== username) || "Your space";
  elements("chatName").textContent = other.startsWith("@") ? other : `@${other}`;
  elements("chatAvatar").textContent = other === "Your space" ? "?" : other.replace(/^@/, "").slice(0, 1).toUpperCase();
  elements("deleteChatButton").hidden = false;
}

function getActivePartner() {
  const chat = chats.find((c) => c.id === activeChatId);
  if (!chat) return null;
  return chat.members.find((m) => m !== username) || null;
}

function updateReadStatusElement(pillElement, messageTs) {
  if (!pillElement) return;
  const partner = getActivePartner();
  const partnerReadTs = partner ? (currentChatReads[partner] || 0) : 0;
  const isRead = partnerReadTs >= messageTs;

  pillElement.innerHTML = isRead
    ? `<span class="read-status read" title="Read by ${partner || 'partner'}">
         <svg class="check-icon" viewBox="0 0 16 16" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
           <polyline points="2.5 8.5 6 12 13.5 4"></polyline>
         </svg>
         <span class="status-label">Read</span>
       </span>`
    : `<span class="read-status sent" title="Sent · Waiting for ${partner || 'partner'} to open chat">
         <span class="status-label">Sent</span>
       </span>`;
}

function updateAllReadStatusIndicators() {
  const pills = elements("messages")?.querySelectorAll(".read-status-pill");
  if (!pills) return;
  pills.forEach((pill) => {
    const ts = Number(pill.dataset.ts);
    if (!isNaN(ts)) {
      updateReadStatusElement(pill, ts);
    }
  });
}

function markActiveChatAsOpened() {
  if (activeChatId && currentUser && username) {
    recordChatOpened(activeChatId, currentUser.uid, username);
  }
}

function setChatStatus(text, connected = false, typing = false) {
  const status = elements("chatStatus");
  if (!status) return;
  status.textContent = text;
  status.classList.toggle("connected", connected);
  status.classList.toggle("typing", typing);
}

function handlePartnerTyping(sender, isTyping) {
  if (!activeChatId) return;
  if (sender === username) return;

  clearTimeout(partnerTypingTimeout);
  if (isTyping) {
    setChatStatus(`${sender} is typing…`, false, true);
    partnerTypingTimeout = setTimeout(async () => {
      const key = await getOrFetchChatKey(activeChatId);
      setChatStatus(key ? "End-to-end encrypted" : "Encryption key missing", Boolean(key), false);
    }, 3500);
  } else {
    getOrFetchChatKey(activeChatId).then((key) => {
      setChatStatus(key ? "End-to-end encrypted" : "Encryption key missing", Boolean(key), false);
    });
  }
}

let unsubscribeFirestoreMessages = null;

async function selectChat(chatId) {
  activeChatId = chatId;
  updateChatHeader(chatId);
  elements("emptyState").hidden = true;
  elements("activeChat").hidden = false;
  elements("chatApp").classList.add("conversation-open");
  elements("messages").replaceChildren();
  renderedMessages = new Set();

  const key = await getOrFetchChatKey(chatId);
  const hasKey = Boolean(key);
  elements("keyWarning").hidden = hasKey;
  elements("msgInput").disabled = !hasKey;
  elements("sendBtn").disabled = !hasKey;
  renderChats();

  clearTimeout(partnerTypingTimeout);
  partnerTypingTimeout = null;
  clearTimeout(typingStopTimeout);
  typingStopTimeout = null;
  isCurrentlyTyping = false;

  if (unsubscribeFirestoreMessages) {
    unsubscribeFirestoreMessages();
    unsubscribeFirestoreMessages = null;
  }
  unsubscribeFirestoreMessages = subscribeToChatMessages(chatId, async (message) => {
    await renderMessage(message, chatId);
  });

  if (unsubscribeChatReads) {
    unsubscribeChatReads();
    unsubscribeChatReads = null;
  }
  currentChatReads = {};
  unsubscribeChatReads = subscribeToChatReads(chatId, (reads) => {
    currentChatReads = reads;
    updateAllReadStatusIndicators();
  });

  if (unsubscribeChatTyping) {
    unsubscribeChatTyping();
    unsubscribeChatTyping = null;
  }
  unsubscribeChatTyping = subscribeToChatTyping(chatId, (typingMap) => {
    const partner = getActivePartner();
    if (partner && typingMap[partner]) {
      handlePartnerTyping(partner, true);
    } else if (partner && !typingMap[partner]) {
      handlePartnerTyping(partner, false);
    }
  });

  markActiveChatAsOpened();
  connectToChat(chatId);
}

function connectToChat(chatId) {
  clearTimeout(reconnectTimer);
  if (socket) socket.close();
  setChatStatus("Connecting");
  let authenticated = false;
  socket = new WebSocket(`${WORKER_URL}?chat=${encodeURIComponent(chatId)}`);
  const activeSocket = socket;
  activeSocket.addEventListener("open", () => activeSocket.send(JSON.stringify({ type: "auth", token })));
  activeSocket.addEventListener("message", async (event) => {
    if (activeSocket !== socket || chatId !== activeChatId) return;
    let data;
    try { data = JSON.parse(event.data); } catch { return; }
    if (data.type === "ready") {
      authenticated = true;
      const key = await getOrFetchChatKey(chatId);
      setChatStatus(key ? "End-to-end encrypted" : "Encryption key missing", Boolean(key));
      for (const message of data.messages || []) await renderMessage(message, chatId);
    } else if (data.type === "chat") {
      handlePartnerTyping(data.message.sender, false);
      await renderMessage(data.message, chatId);
    } else if (data.type === "chat_updated") {
      upsertChat(data.chat);
      updateChatHeader(chatId);
    } else if (data.type === "typing") {
      handlePartnerTyping(data.sender, Boolean(data.active));
    } else if (data.type === "chat_deleted") {
      forgetChat(chatId);
    } else if (data.type === "error") {
      authenticated = false;
      setChatStatus(data.error || "Connection rejected");
    }
  });
  activeSocket.addEventListener("close", () => {
    if (activeSocket !== socket || chatId !== activeChatId) return;
    if (!authenticated) setChatStatus("Disconnected");
    else {
      setChatStatus("Reconnecting…");
      reconnectTimer = setTimeout(() => { if (activeChatId === chatId) connectToChat(chatId); }, 2000);
    }
  });
  activeSocket.addEventListener("error", () => {
    if (activeSocket === socket && chatId === activeChatId) setChatStatus("Connection error");
  });
}

async function renderMessage(message, chatId) {
  if (chatId !== activeChatId) return;
  const messageId = message.id || `${message.ts}:${message.sender}`;
  if (renderedMessages.has(messageId)) return;
  renderedMessages.add(messageId);

  let text;
  try {
    const key = await importChatKey(await getOrFetchChatKey(chatId));
    text = await decryptMessage(key, message.text);
  } catch {
    text = "Message could not be decrypted.";
  }

  const isMine = message.sender === username;
  const row = document.createElement("article");
  row.className = `message-row${isMine ? " mine" : ""}`;
  const bubble = document.createElement("div");
  bubble.className = "message-bubble";
  bubble.textContent = text;
  
  const meta = document.createElement("div");
  meta.className = "message-meta";
  const time = new Date(message.ts);
  const timeSpan = document.createElement("span");
  timeSpan.className = "message-time";
  timeSpan.textContent = `${isMine ? "You" : message.sender} · ${time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
  meta.append(timeSpan);

  if (isMine) {
    const statusPill = document.createElement("span");
    statusPill.className = "read-status-pill";
    statusPill.dataset.ts = String(message.ts);
    updateReadStatusElement(statusPill, message.ts);
    meta.append(statusPill);
  }

  row.append(bubble, meta);
  elements("messages").append(row);
  elements("messages").scrollTop = elements("messages").scrollHeight;

  if (!isMine && !document.hidden) {
    markActiveChatAsOpened();
  }
}

function forgetChat(chatId) {
  chats = chats.filter((chat) => chat.id !== chatId);
  localStorage.removeItem(`${CHAT_KEY_PREFIX}${chatId}`);
  renderChats();
  if (activeChatId !== chatId) return;
  if (unsubscribeChatReads) {
    unsubscribeChatReads();
    unsubscribeChatReads = null;
  }
  if (unsubscribeChatTyping) {
    unsubscribeChatTyping();
    unsubscribeChatTyping = null;
  }
  clearTimeout(partnerTypingTimeout);
  partnerTypingTimeout = null;
  sendTyping(false);
  currentChatReads = {};
  clearTimeout(reconnectTimer);
  const oldSocket = socket;
  socket = null;
  activeChatId = "";
  if (oldSocket && oldSocket.readyState < WebSocket.CLOSING) oldSocket.close();
  elements("activeChat").hidden = true;
  elements("emptyState").hidden = false;
  elements("chatApp").classList.remove("conversation-open");
  elements("messages").replaceChildren();
  showToast("Chat deleted.");
}

async function sendMessage(event) {
  event.preventDefault();
  const input = elements("msgInput");
  const text = input.value.trim();
  if (!text || !activeChatId) return;

  try {
    const rawKey = await getOrFetchChatKey(activeChatId);
    if (!rawKey) {
      showToast("Missing encryption key for this chat.");
      return;
    }
    const key = await importChatKey(rawKey);
    const encryptedText = await encryptMessage(key, text);
    const messageData = {
      id: crypto.randomUUID(),
      chatId: activeChatId,
      sender: username,
      text: encryptedText,
      ts: Date.now()
    };

    // Save to Firestore for reliable multi-user sync & persistent history
    await saveFirestoreMessage(activeChatId, messageData);

    // Also send via WebSocket if connected
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: "chat", text: encryptedText }));
    }

    // Render immediately in active chat
    await renderMessage(messageData, activeChatId);

    input.value = "";
    input.style.height = "auto";
    sendTyping(false);
    markActiveChatAsOpened();
  } catch (err) {
    console.error("Send error:", err);
    showToast("Couldn't encrypt that message on this device.");
  }
}

function sendTyping(active) {
  if (!activeChatId) return;

  if (active) {
    const now = Date.now();
    if (!isCurrentlyTyping || (now - lastTypingSentAt >= 1500)) {
      isCurrentlyTyping = true;
      lastTypingSentAt = now;

      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "typing", active: true }));
      }
      if (currentUser && activeChatId) {
        recordUserTyping(activeChatId, currentUser.uid, username, true);
      }
    }

    clearTimeout(typingStopTimeout);
    typingStopTimeout = setTimeout(() => {
      sendTyping(false);
    }, 2500);
  } else {
    clearTimeout(typingStopTimeout);
    if (isCurrentlyTyping) {
      isCurrentlyTyping = false;
      lastTypingSentAt = 0;
      if (socket && socket.readyState === WebSocket.OPEN) {
        socket.send(JSON.stringify({ type: "typing", active: false }));
      }
      if (currentUser && activeChatId) {
        recordUserTyping(activeChatId, currentUser.uid, username, false);
      }
    }
  }
}

function showToast(message) {
  const toast = elements("toast");
  toast.textContent = message;
  toast.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { toast.hidden = true; }, 3000);
}

// Instagram Style New Message Modal and User Discovery
async function openNewChatModal() {
  elements("newChatError").textContent = "";
  elements("userSearchInput").value = "";
  elements("newChatModal").showModal();
  await loadAndRenderSuggestedUsers();
}

async function loadAndRenderSuggestedUsers() {
  const container = elements("suggestedUsersList");
  container.innerHTML = '<div class="list-empty">Finding registered people…</div>';
  try {
    registeredUsers = await getAllRegisteredUsers(username);
    renderSuggestedUsersList();
  } catch (err) {
    container.innerHTML = '<div class="list-empty">Could not load users.</div>';
  }
}

function renderSuggestedUsersList() {
  const container = elements("suggestedUsersList");
  const filter = elements("userSearchInput").value.trim().toLowerCase().replace(/^@/, "");
  const filtered = registeredUsers.filter((u) => u.username.toLowerCase().includes(filter));

  container.replaceChildren();
  if (filtered.length === 0) {
    const empty = document.createElement("div");
    empty.className = "list-empty";
    empty.textContent = filter ? `No user found matching "@${filter}"` : "No other users registered yet.";
    container.append(empty);
    return;
  }

  for (const user of filtered) {
    const row = document.createElement("div");
    row.className = "suggested-user-row";

    const info = document.createElement("div");
    info.className = "suggested-user-info";

    const avatar = document.createElement("span");
    avatar.className = "avatar";
    avatar.textContent = user.username.slice(0, 1).toUpperCase();

    const name = document.createElement("strong");
    name.textContent = `@${user.username}`;
    info.append(avatar, name);

    const chatBtn = document.createElement("button");
    chatBtn.type = "button";
    chatBtn.className = "primary chat-user-btn";
    chatBtn.textContent = "Chat";
    chatBtn.addEventListener("click", () => startDirectChatWith(user));

    row.append(info, chatBtn);
    container.append(row);
  }
}

async function startDirectChatWith(targetUser) {
  elements("newChatError").textContent = "";
  try {
    // 1. Check if a conversation already exists
    const existing = chats.find((c) => c.members.includes(targetUser.username));
    if (existing) {
      elements("newChatModal").close();
      selectChat(existing.id);
      return;
    }

    // 2. Generate new AES-256 key
    const chatKey = await generateChatKey();
    const chatId = crypto.randomUUID();

    // 3. Save key for current user
    saveChatKey(chatId, chatKey);

    // 4. Send Instagram-style Direct Message Request
    await sendDirectChatRequest({
      senderUid: currentUser.uid,
      senderUsername: username,
      recipientUid: targetUser.uid,
      recipientUsername: targetUser.username,
      chatId,
      chatKey
    });

    // 5. Add to local chats
    const newChat = {
      id: chatId,
      members: [username, targetUser.username],
      createdAt: Date.now()
    };
    upsertChat(newChat);

    elements("newChatModal").close();
    selectChat(chatId);
    showToast(`Chat request sent to @${targetUser.username}. Message away!`);
  } catch (err) {
    elements("newChatError").textContent = err.message || "Failed to start conversation.";
  }
}

async function deleteCurrentChat() {
  const chatId = activeChatId;
  if (!chatId) return;
  elements("confirmDelete").disabled = true;
  elements("deleteError").textContent = "";
  try {
    await api(`/api/chats/${encodeURIComponent(chatId)}`, { method: "DELETE" }).catch(() => {});
    elements("deleteDialog").close();
    forgetChat(chatId);
  } catch (error) {
    elements("deleteError").textContent = error.message;
  } finally {
    elements("confirmDelete").disabled = false;
  }
}

// Event Listeners
elements("authSwitch").addEventListener("click", () => showAuthMode(authMode === "login" ? "register" : "login"));

elements("passwordToggle").addEventListener("click", () => {
  const input = elements("passwordInput");
  const reveal = input.type === "password";
  input.type = reveal ? "text" : "password";
  elements("passwordToggle").setAttribute("aria-label", reveal ? "Hide password" : "Show password");
  elements("passwordToggle").setAttribute("aria-pressed", String(reveal));
  elements("passwordToggle").title = reveal ? "Hide password" : "Show password";
});

function setGoogleButtonLoading(loading) {
  const btn = elements("googleAuthButton");
  const textSpan = elements("googleAuthText");
  if (!btn) return;
  btn.disabled = loading;
  if (loading) {
    if (textSpan) textSpan.textContent = "Connecting to Google...";
    btn.style.opacity = "0.75";
  } else {
    if (textSpan) textSpan.textContent = "Continue with Google";
    btn.style.opacity = "1";
  }
}

function clearAuthErrors() {
  if (elements("authError")) elements("authError").textContent = "";
  if (elements("googleAuthError")) elements("googleAuthError").textContent = "";
  if (elements("googleAuthFeedback")) elements("googleAuthFeedback").hidden = true;
  if (elements("googleAuthActions")) elements("googleAuthActions").hidden = true;
}

function handleGoogleAuthError(error) {
  const code = error?.code || "";
  const msg = error?.message || String(error);
  const feedback = elements("googleAuthFeedback");
  const errorText = elements("googleAuthError");
  const actions = elements("googleAuthActions");

  if (!feedback || !errorText) return;
  feedback.hidden = false;

  if (code === "auth/popup-blocked" || msg.includes("popup-blocked") || msg.includes("blocked by the browser")) {
    errorText.textContent = "Google sign-in popup was blocked by your browser. Try Redirect or Open in a New Tab:";
    if (actions) actions.hidden = false;
  } else if (code === "auth/popup-closed-by-user") {
    errorText.textContent = "Sign-in was cancelled. Click above to try again.";
  } else if (code === "auth/cancelled-popup-request") {
    errorText.textContent = "Sign-in already in progress in another window.";
  } else if (code === "auth/unauthorized-domain") {
    errorText.innerHTML = `Domain (<code>${window.location.hostname}</code>) is not on Firebase Authorized Domains.<br>Use <strong>⚡ Instant Demo Account</strong> below to test immediately!`;
  } else {
    errorText.textContent = msg.replace("Firebase: ", "").replace(/\(auth\/[^)]+\)/, "");
  }
}

// Check if user is returning from a redirect sign-in
getRedirectResult(auth)
  .then(async (credential) => {
    if (credential && credential.user) {
      await handleUserAuthenticated(credential.user);
    }
  })
  .catch((err) => {
    console.error("Redirect credential error:", err);
    handleGoogleAuthError(err);
  });

// Google Authentication
elements("googleAuthButton").addEventListener("click", async () => {
  clearAuthErrors();
  setGoogleButtonLoading(true);
  try {
    const res = await signInWithPopup(auth, googleProvider);
    if (res && res.user) {
      await handleUserAuthenticated(res.user);
    }
  } catch (error) {
    console.error("Google sign-in error:", error);
    handleGoogleAuthError(error);
  } finally {
    setGoogleButtonLoading(false);
  }
});

// Google Redirect fallback
elements("googleRedirectBtn")?.addEventListener("click", async () => {
  clearAuthErrors();
  setGoogleButtonLoading(true);
  try {
    await signInWithRedirect(auth, googleProvider);
  } catch (err) {
    handleGoogleAuthError(err);
    setGoogleButtonLoading(false);
  }
});

// Open external tab
elements("openExternalBtn")?.addEventListener("click", () => {
  window.open(window.location.href, "_blank");
});

// Instant Demo Account
elements("demoLoginBtn")?.addEventListener("click", async () => {
  clearAuthErrors();
  const demoUid = `demo_${Math.random().toString(36).substring(2, 9)}`;
  const demoHandle = `tester_${Math.random().toString(36).substring(2, 6)}`;
  const fakeUser = {
    uid: demoUid,
    email: `${demoHandle}@duochat.local`,
    displayName: `Tester (@${demoHandle})`
  };
  currentUser = fakeUser;
  try {
    await claimUsername(demoUid, demoHandle, fakeUser.email);
  } catch {
    // claim fallback
  }
  await handleUserAuthenticated(fakeUser);
  showToast(`Signed in as @${demoHandle}!`);
});

// Email / Password Authentication
elements("authForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = elements("authSubmit");
  button.disabled = true;
  clearAuthErrors();

  const email = elements("emailInput").value.trim();
  const password = elements("passwordInput").value;
  const desiredUsername = elements("usernameInput").value.trim().toLowerCase();

  try {
    if (authMode === "register") {
      if (!desiredUsername) {
        throw new Error("Please enter a username handle for DuoChat.");
      }
      if (!/^[a-z0-9_]{3,24}$/.test(desiredUsername)) {
        throw new Error("Username must be 3-24 characters, numbers, or underscores.");
      }
      const cred = await createUserWithEmailAndPassword(auth, email, password);
      await claimUsername(cred.user.uid, desiredUsername, email);
    } else {
      await signInWithEmailAndPassword(auth, email, password);
    }
  } catch (error) {
    console.error("Auth error:", error);
    elements("authError").textContent = error.message.replace("Firebase: ", "");
  } finally {
    button.disabled = false;
  }
});

// Handle Modal for setting username
elements("handleForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const submitBtn = elements("handleModalSubmit");
  submitBtn.disabled = true;
  elements("handleError").textContent = "";

  const chosenUsername = elements("handleModalInput").value.trim().toLowerCase();
  try {
    if (!currentUser) throw new Error("No active user.");
    await claimUsername(currentUser.uid, chosenUsername, currentUser.email);
    elements("handleModal").close();
    await handleUserAuthenticated(currentUser);
  } catch (err) {
    elements("handleError").textContent = err.message;
  } finally {
    submitBtn.disabled = false;
  }
});

// Sign out
elements("signoutButton").addEventListener("click", async () => {
  try {
    await fbSignOut(auth);
  } catch (err) {
    console.error("Signout error:", err);
  }
  if (unsubscribeChatReads) {
    unsubscribeChatReads();
    unsubscribeChatReads = null;
  }
  if (unsubscribeChatTyping) {
    unsubscribeChatTyping();
    unsubscribeChatTyping = null;
  }
  if (unsubscribeRequests) {
    unsubscribeRequests();
    unsubscribeRequests = null;
  }
  clearTimeout(partnerTypingTimeout);
  partnerTypingTimeout = null;
  sendTyping(false);
  currentChatReads = {};
  clearTimeout(reconnectTimer);
  if (socket) socket.close();
  socket = null;
  currentUser = null;
  token = "";
  username = "";
  chats = [];
  pendingRequests = [];
  activeChatId = "";
  elements("chatApp").hidden = true;
  elements("activeChat").hidden = true;
  elements("emptyState").hidden = false;
  elements("chatApp").classList.remove("conversation-open");
  elements("messages").replaceChildren();
  elements("signinScreen").hidden = false;
  elements("passwordInput").value = "";
  showAuthMode("login");
});

// Inbox Tabs
elements("tabMessages").addEventListener("click", () => switchInboxTab("messages"));
elements("tabRequests").addEventListener("click", () => switchInboxTab("requests"));

// Instagram Style Compose / New Chat
elements("newChatButton").addEventListener("click", openNewChatModal);
elements("emptyStartButton").addEventListener("click", openNewChatModal);
elements("refreshUsersBtn").addEventListener("click", loadAndRenderSuggestedUsers);
elements("userSearchInput").addEventListener("input", renderSuggestedUsersList);

elements("chatSearch").addEventListener("input", renderChats);
elements("messageForm").addEventListener("submit", sendMessage);
elements("msgInput").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    elements("messageForm").requestSubmit();
  }
});
elements("msgInput").addEventListener("input", (event) => {
  const field = event.target;
  field.style.height = "auto";
  field.style.height = `${Math.min(field.scrollHeight, 130)}px`;
  sendTyping(field.value.trim().length > 0);
});
elements("msgInput").addEventListener("blur", () => {
  sendTyping(false);
});

elements("deleteChatButton").addEventListener("click", () => elements("deleteDialog").showModal());
elements("deleteForm").addEventListener("submit", (event) => { event.preventDefault(); deleteCurrentChat(); });
elements("backButton").addEventListener("click", () => elements("chatApp").classList.remove("conversation-open"));
document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => elements(button.dataset.close).close()));

// Window focus listeners
window.addEventListener("focus", () => {
  if (activeChatId && !elements("activeChat").hidden) {
    markActiveChatAsOpened();
  }
});
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && activeChatId && !elements("activeChat").hidden) {
    markActiveChatAsOpened();
  }
});
elements("msgInput").addEventListener("focus", () => {
  if (activeChatId) {
    markActiveChatAsOpened();
  }
});

// Listen to Firebase Auth state
onAuthStateChanged(auth, async (user) => {
  if (user) {
    await handleUserAuthenticated(user);
  } else {
    elements("signinScreen").hidden = false;
    elements("chatApp").hidden = true;
  }
});
