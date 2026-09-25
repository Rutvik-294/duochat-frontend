import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import {
  auth,
  googleProvider,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
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
} from './firebase.js';

// Types
interface UserProfile {
  uid: string;
  username: string;
  email?: string;
  displayName?: string;
}

interface Chat {
  id: string;
  members: string[];
  lastMessage?: string;
  lastMessageSender?: string;
  lastMessageTimestamp?: number;
  createdAt?: number;
  updatedAt?: number;
}

interface Message {
  id: string;
  chatId: string;
  sender: string;
  payload: string;
  decryptedText?: string;
  timestamp: number;
}

interface ChatRequest {
  id: string;
  senderUid: string;
  senderUsername: string;
  recipientUid: string;
  recipientUsername: string;
  chatId: string;
  chatKey: string;
  createdAt: number;
}

interface RegisteredUser {
  uid: string;
  username: string;
  email?: string;
  createdAt?: number;
}

const CHAT_KEY_PREFIX = 'duochat:key:';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

// Robust Base64URL encoding/decoding
function bytesToBase64Url(bytes: Uint8Array | ArrayBuffer): string {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let binary = '';
  for (let i = 0; i < u8.byteLength; i++) {
    binary += String.fromCharCode(u8[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlToBytes(value: string): Uint8Array {
  if (!value || typeof value !== 'string') throw new Error('Invalid base64 string');
  let base64 = value.trim().replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  if (pad) {
    base64 += '='.repeat(4 - pad);
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function generateChatKey(): Promise<string> {
  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  return bytesToBase64Url(rawKey);
}

async function importChatKey(encodedKey: string): Promise<CryptoKey> {
  if (!encodedKey) throw new Error('Missing encryption key');
  const bytes = base64UrlToBytes(encodedKey.trim());
  if (bytes.length !== 32) throw new Error('Invalid encryption key length');
  return crypto.subtle.importKey('raw', bytes as unknown as ArrayBuffer, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptMessage(key: CryptoKey, text: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoder.encode(text));
  return JSON.stringify({ iv: bytesToBase64Url(iv), ct: bytesToBase64Url(ciphertext) });
}

async function decryptMessage(key: CryptoKey, payload: string): Promise<string> {
  try {
    const encrypted = typeof payload === 'string' && payload.startsWith('{"iv":') ? JSON.parse(payload) : null;
    if (encrypted && encrypted.iv && encrypted.ct) {
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: base64UrlToBytes(encrypted.iv) as unknown as ArrayBuffer },
        key,
        base64UrlToBytes(encrypted.ct) as unknown as ArrayBuffer
      );
      return decoder.decode(plaintext);
    }
  } catch (err) {
    console.warn('Decryption failed, falling back:', err);
  }
  if (typeof payload === 'string' && !payload.startsWith('{"iv":')) {
    return payload;
  }
  return '[Encrypted message]';
}

export default function App() {
  // Authentication State
  const [currentUser, setCurrentUser] = useState<UserProfile | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [googleError, setGoogleError] = useState('');
  const [showRedirectOption, setShowRedirectOption] = useState(false);

  // App & Navigation State
  const [chats, setChats] = useState<Chat[]>([]);
  const [activeChatId, setActiveChatId] = useState<string>('');
  const [activeInboxTab, setActiveInboxTab] = useState<'messages' | 'requests'>('messages');
  const [searchFilter, setSearchFilter] = useState('');
  const [mobileConversationOpen, setMobileConversationOpen] = useState(false);

  // Active Chat State
  const [messages, setMessages] = useState<Message[]>([]);
  const [messageText, setMessageText] = useState('');
  const [cryptoKey, setCryptoKey] = useState<CryptoKey | null>(null);
  const [partnerTyping, setPartnerTyping] = useState(false);
  const [chatReads, setChatReads] = useState<Record<string, number>>({});

  // Requests & Users State
  const [pendingRequests, setPendingRequests] = useState<ChatRequest[]>([]);
  const [registeredUsers, setRegisteredUsers] = useState<RegisteredUser[]>([]);
  const [userSearchTerm, setUserSearchTerm] = useState('');
  const [loadingUsers, setLoadingUsers] = useState(false);

  // Modals & UI
  const [showNewChatModal, setShowNewChatModal] = useState(false);
  const [showHandleModal, setShowHandleModal] = useState(false);
  const [handleModalInput, setHandleModalInput] = useState('');
  const [handleModalError, setHandleModalError] = useState('');
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [newChatError, setNewChatError] = useState('');
  const [toastMessage, setToastMessage] = useState('');

  // Refs
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const toastTimeoutRef = useRef<number | null>(null);
  const typingTimeoutRef = useRef<number | null>(null);
  const lastTypingSentRef = useRef<number>(0);

  const showToast = useCallback((msg: string) => {
    setToastMessage(msg);
    if (toastTimeoutRef.current) clearTimeout(toastTimeoutRef.current);
    toastTimeoutRef.current = window.setTimeout(() => setToastMessage(''), 3500);
  }, []);

  // Save chat key locally and to Firestore
  const persistChatKey = useCallback((chatId: string, keyStr: string) => {
    try {
      localStorage.setItem(`${CHAT_KEY_PREFIX}${chatId}`, keyStr);
      if (currentUser?.uid) {
        savePersistentChatKey(chatId, currentUser.uid, keyStr);
      }
    } catch (e) {
      console.warn('Could not persist chat key:', e);
    }
  }, [currentUser]);

  // Load chat key
  const loadChatKey = useCallback(async (chatId: string): Promise<string> => {
    let key = localStorage.getItem(`${CHAT_KEY_PREFIX}${chatId}`);
    if (key) return key;
    if (currentUser?.uid) {
      key = await getPersistentChatKey(chatId, currentUser.uid);
      if (key) {
        localStorage.setItem(`${CHAT_KEY_PREFIX}${chatId}`, key);
        return key;
      }
    }
    return '';
  }, [currentUser]);

  // Handle User Authenticated
  const handleAuthenticatedUser = useCallback(async (user: any) => {
    setAuthLoading(true);
    let profile = await getUserProfile(user.uid);

    // Auto-generate or claim handle
    if (!profile || !profile.username) {
      let proposed = '';
      if (user.displayName) {
        proposed = user.displayName.toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20);
      }
      if (!proposed || proposed.length < 3) {
        if (user.email) {
          proposed = user.email.split('@')[0].toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20);
        }
      }
      if (proposed && proposed.length >= 3) {
        try {
          profile = await claimUsername(user.uid, proposed, user.email || '');
        } catch {
          // Fallback if handle is taken
        }
      }
    }

    if (!profile || !profile.username) {
      const fallbackHandle = user.email ? user.email.split('@')[0] : `user_${user.uid.slice(0, 6)}`;
      setHandleModalInput(fallbackHandle);
      setCurrentUser({
        uid: user.uid,
        email: user.email,
        displayName: user.displayName,
        username: ''
      });
      setShowHandleModal(true);
      setAuthLoading(false);
      return;
    }

    setCurrentUser({
      uid: user.uid,
      email: user.email || (profile as any)?.email || '',
      displayName: user.displayName || profile.username,
      username: profile.username
    });
    setAuthLoading(false);
  }, []);

  // Listen to Firebase Auth state
  useEffect(() => {
    const unsub = onAuthStateChanged(auth, async (user: any) => {
      if (user) {
        await handleAuthenticatedUser(user);
      } else {
        // If not signed into Firebase and not in a demo session
        setCurrentUser((prev) => (prev?.uid.startsWith('demo_') ? prev : null));
        setAuthLoading(false);
      }
    });

    // Check redirect credential safely
    getRedirectResult(auth)
      .then((cred: any) => {
        if (cred && cred.user) {
          handleAuthenticatedUser(cred.user);
        }
      })
      .catch((err: any) => {
        console.error('Google redirect sign-in failed:', err);
        setGoogleError(getGoogleAuthMessage(err));
      });

    return () => unsub();
  }, [handleAuthenticatedUser]);

  // Subscribe to user's chats
  useEffect(() => {
    if (!currentUser?.username) return;

    const unsub = subscribeToUserChats(currentUser.username, (updatedChats: Chat[]) => {
      setChats(updatedChats);
    });

    return () => unsub();
  }, [currentUser?.username]);

  // Subscribe to incoming requests
  useEffect(() => {
    if (!currentUser?.uid) return;

    const unsub = subscribeToIncomingRequests(currentUser.uid, (requests: ChatRequest[]) => {
      setPendingRequests(requests);
    });

    return () => unsub();
  }, [currentUser?.uid]);

  // Active chat: Setup Key, Read Receipts, Typing, and Message Stream
  useEffect(() => {
    if (!activeChatId || !currentUser) {
      setCryptoKey(null);
      setMessages([]);
      return;
    }

    let isMounted = true;

    // 1. Get or create encryption key
    loadChatKey(activeChatId).then(async (keyStr) => {
      if (!isMounted) return;
      if (!keyStr) {
        // Generate new key and persist
        const newKey = await generateChatKey();
        persistChatKey(activeChatId, newKey);
        keyStr = newKey;
      }
      try {
        const imported = await importChatKey(keyStr);
        if (isMounted) setCryptoKey(imported);
      } catch (e) {
        console.error('Failed to import chat key:', e);
      }
    });

    // 2. Mark chat as opened
    recordChatOpened(activeChatId, currentUser.uid);

    // 3. Subscribe to read receipts
    const unsubReads = subscribeToChatReads(activeChatId, (reads: Record<string, number>) => {
      if (isMounted) setChatReads(reads);
    });

    // 4. Subscribe to typing indicator
    const unsubTyping = subscribeToChatTyping(activeChatId, (typingMap: Record<string, any>) => {
      if (!isMounted) return;
      const partnerIsTyping = Object.entries(typingMap).some(([uid, data]) => {
        return uid !== currentUser.uid && data.isTyping && Date.now() - (data.updatedAt || 0) < 5000;
      });
      setPartnerTyping(partnerIsTyping);
    });

    return () => {
      isMounted = false;
      unsubReads();
      unsubTyping();
      recordUserTyping(activeChatId, currentUser.uid, false);
    };
  }, [activeChatId, currentUser, loadChatKey, persistChatKey]);

  // Decrypt and listen to chat messages
  useEffect(() => {
    if (!activeChatId) return;

    const unsub = subscribeToChatMessages(activeChatId, async (incomingMsgs: Message[]) => {
      // Sort chronologically
      const sorted = [...incomingMsgs].sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));

      // Decrypt messages if key is ready
      if (cryptoKey) {
        const decryptedList = await Promise.all(
          sorted.map(async (msg) => {
            const text = await decryptMessage(cryptoKey, msg.payload);
            return { ...msg, decryptedText: text };
          })
        );
        setMessages(decryptedList);
      } else {
        setMessages(sorted.map((m) => ({ ...m, decryptedText: m.payload })));
      }
    });

    return () => unsub();
  }, [activeChatId, cryptoKey]);

  // Auto-scroll messages to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, partnerTyping]);

  const getGoogleAuthMessage = (err: any) => {
    const code = err?.code || '';
    const host = window.location.hostname;
    if (code === 'auth/unauthorized-domain') {
      return `Google sign-in is blocked for ${host}. In Firebase Console, open Authentication → Settings → Authorized domains and add ${host}.`;
    }
    if (code === 'auth/operation-not-allowed') {
      return 'Google sign-in is disabled for this Firebase project. Enable the Google provider in Authentication → Sign-in method.';
    }
    if (code === 'auth/popup-blocked') {
      return 'Your browser blocked the Google sign-in popup. Use Continue with redirect below.';
    }
    if (code === 'auth/popup-closed-by-user') {
      return 'The Google sign-in window was closed before sign-in completed.';
    }
    return (err?.message || 'Google sign-in failed. Please try again.').replace('Firebase: ', '');
  };

  // Google-only sign-in
  const handleGoogleSignIn = async () => {
    setGoogleError('');
    setShowRedirectOption(false);
    setGoogleLoading(true);
    try {
      const res = await signInWithPopup(auth, googleProvider);
      if (res && res.user) {
        await handleAuthenticatedUser(res.user);
      }
    } catch (err: any) {
      console.error('Google Sign-in error:', err);
      if (err?.code === 'auth/popup-blocked') {
        setGoogleError(getGoogleAuthMessage(err));
        setShowRedirectOption(true);
      } else {
        setGoogleError(getGoogleAuthMessage(err));
      }
    } finally {
      setGoogleLoading(false);
    }
  };

  const handleGoogleRedirect = async () => {
    setGoogleError('');
    setShowRedirectOption(false);
    setGoogleLoading(true);
    try {
      await signInWithRedirect(auth, googleProvider);
    } catch (err: any) {
      console.error('Google redirect sign-in failed:', err);
      setGoogleError(getGoogleAuthMessage(err));
      setGoogleLoading(false);
    }
  };

  // Handle Modal Submit
  const handleClaimModalSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setHandleModalError('');
    const chosen = handleModalInput.trim().toLowerCase();
    if (!chosen || !/^[a-z0-9_]{3,24}$/.test(chosen)) {
      setHandleModalError('Must be 3-24 characters, letters, numbers, or underscores.');
      return;
    }
    try {
      if (!currentUser?.uid) return;
      await claimUsername(currentUser.uid, chosen, currentUser.email || '');
      setCurrentUser((prev) => (prev ? { ...prev, username: chosen } : null));
      setShowHandleModal(false);
      showToast(`Handle set to @${chosen}`);
    } catch (err: any) {
      setHandleModalError(err.message || 'Could not claim handle');
    }
  };

  // Sign out
  const handleSignOut = async () => {
    try {
      await fbSignOut(auth);
    } catch (e) {
      console.warn('Signout notice:', e);
    }
    setCurrentUser(null);
    setActiveChatId('');
    setChats([]);
    setMessages([]);
    setMobileConversationOpen(false);
  };

  // Send Message
  const handleSendMessage = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const text = messageText.trim();
    if (!text || !activeChatId || !currentUser) return;

    setMessageText('');
    recordUserTyping(activeChatId, currentUser.uid, false);

    try {
      let payload = text;
      if (cryptoKey) {
        payload = await encryptMessage(cryptoKey, text);
      }

      await saveFirestoreMessage(activeChatId, {
        chatId: activeChatId,
        sender: currentUser.username,
        payload,
        timestamp: Date.now()
      });

      // Update chat's last message
      const activeChat = chats.find((c) => c.id === activeChatId);
      if (activeChat) {
        await saveFirestoreChat({
          ...activeChat,
          lastMessage: text,
          lastMessageSender: currentUser.username,
          lastMessageTimestamp: Date.now(),
          updatedAt: Date.now()
        });
      }
    } catch (err: any) {
      console.error('Error sending message:', err);
      showToast('Could not send message. Please retry.');
    }
  };

  // Typing Input Handler
  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const val = e.target.value;
    setMessageText(val);

    if (!activeChatId || !currentUser) return;

    const now = Date.now();
    if (val.trim().length > 0) {
      if (now - lastTypingSentRef.current > 2000) {
        recordUserTyping(activeChatId, currentUser.uid, true);
        lastTypingSentRef.current = now;
      }
      if (typingTimeoutRef.current) clearTimeout(typingTimeoutRef.current);
      typingTimeoutRef.current = window.setTimeout(() => {
        recordUserTyping(activeChatId, currentUser.uid, false);
      }, 3000);
    } else {
      recordUserTyping(activeChatId, currentUser.uid, false);
    }
  };

  // Load registered users for modal
  const loadUsers = async () => {
    setLoadingUsers(true);
    try {
      const list = await getAllRegisteredUsers(currentUser?.uid || '');
      setRegisteredUsers(list);
    } catch (err) {
      console.warn('Failed to load users:', err);
    } finally {
      setLoadingUsers(false);
    }
  };

  const openNewChat = () => {
    setShowNewChatModal(true);
    setNewChatError('');
    loadUsers();
  };

  // Start chat with user directly
  const handleStartChatWithUser = async (targetUser: RegisteredUser) => {
    if (!currentUser?.username) return;
    setNewChatError('');

    try {
      // Check if chat already exists
      const existing = chats.find((c) => c.members.includes(targetUser.username));
      if (existing) {
        setActiveChatId(existing.id);
        setShowNewChatModal(false);
        setMobileConversationOpen(true);
        return;
      }

      // Create new chat
      const chatId = `chat_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
      const keyStr = await generateChatKey();
      persistChatKey(chatId, keyStr);

      const newChat: Chat = {
        id: chatId,
        members: [currentUser.username, targetUser.username],
        createdAt: Date.now(),
        updatedAt: Date.now()
      };

      await saveFirestoreChat(newChat);

      // Send request to target user
      await sendDirectChatRequest({
        senderUid: currentUser.uid,
        senderUsername: currentUser.username,
        recipientUid: targetUser.uid,
        recipientUsername: targetUser.username,
        chatId,
        chatKey: keyStr
      });

      setShowNewChatModal(false);
      setActiveChatId(chatId);
      setMobileConversationOpen(true);
      showToast(`Chat request sent to @${targetUser.username}!`);
    } catch (err: any) {
      setNewChatError(err.message || 'Could not start conversation.');
    }
  };

  // Accept DM request
  const handleAcceptRequest = async (req: ChatRequest) => {
    if (!currentUser?.uid) return;
    try {
      await acceptDirectChatRequest(req, currentUser.uid);
      persistChatKey(req.chatId, req.chatKey);

      let chat = chats.find((c) => c.id === req.chatId);
      if (!chat) {
        chat = {
          id: req.chatId,
          members: [currentUser.username, req.senderUsername],
          createdAt: req.createdAt,
          updatedAt: Date.now()
        };
        await saveFirestoreChat(chat);
      }

      setActiveInboxTab('messages');
      setActiveChatId(req.chatId);
      setMobileConversationOpen(true);
      showToast(`Accepted request from @${req.senderUsername}`);
    } catch (err: any) {
      showToast(err.message || 'Could not accept request.');
    }
  };

  // Decline DM request
  const handleDeclineRequest = async (req: ChatRequest) => {
    try {
      await declineDirectChatRequest(req.id);
      showToast(`Declined request from @${req.senderUsername}`);
    } catch {
      showToast('Could not decline request.');
    }
  };

  // Delete chat
  const handleDeleteChat = async () => {
    if (!activeChatId) return;
    try {
      await deleteFirestoreChat(activeChatId);
      setChats((prev) => prev.filter((c) => c.id !== activeChatId));
      setActiveChatId('');
      setMobileConversationOpen(false);
      setShowDeleteModal(false);
      showToast('Conversation deleted.');
    } catch (err: any) {
      showToast(err.message || 'Could not delete conversation.');
    }
  };

  // Active chat partner
  const activeChat = useMemo(() => chats.find((c) => c.id === activeChatId), [chats, activeChatId]);
  const partnerUsername = useMemo(() => {
    if (!activeChat || !currentUser?.username) return '';
    return activeChat.members.find((m) => m !== currentUser.username) || activeChat.members[0];
  }, [activeChat, currentUser?.username]);

  // Filtered chats
  const visibleChats = useMemo(() => {
    if (!currentUser?.username) return [];
    const term = searchFilter.trim().toLowerCase();
    return chats.filter((c) => {
      const partner = c.members.find((m) => m !== currentUser.username) || '';
      return partner.toLowerCase().includes(term);
    });
  }, [chats, searchFilter, currentUser?.username]);

  // Filtered suggested users
  const visibleUsers = useMemo(() => {
    const term = userSearchTerm.trim().toLowerCase();
    return registeredUsers.filter((u) => u.username.toLowerCase().includes(term));
  }, [registeredUsers, userSearchTerm]);

  // If Auth is loading
  if (authLoading) {
    return (
      <div style={{ display: 'grid', placeItems: 'center', minHeight: '100vh', background: '#0b1217', color: '#a6efc5' }}>
        <div style={{ textAlign: 'center' }}>
          <div className="brand-mark" style={{ margin: '0 auto 16px', width: 48, height: 48, fontSize: 28 }}>✳</div>
          <p style={{ letterSpacing: '0.1em', fontSize: 13 }}>CONNECTING TO DUOCHAT...</p>
        </div>
      </div>
    );
  }

  // If user is not authenticated: Show Sign In screen
  if (!currentUser || !currentUser.username) {
    return (
      <section className="signin-screen">
        <main className="login-card">
          <a className="brand" href="#" aria-label="DuoChat home">
            <span className="brand-mark" aria-hidden="true">✳</span>
            <span>duochat<span className="brand-dot">.</span></span>
          </a>
          <p className="eyebrow">YOUR PRIVATE CORNER</p>
          <h1>Good conversations<br />start here.</h1>
          <p className="auth-description">Sign in with Google to get back to your space. Just you, your person, and the conversation.</p>

          {/* Google Sign In */}
          <button
            className="google-auth-button"
            type="button"
            onClick={handleGoogleSignIn}
            disabled={googleLoading}
            aria-busy={googleLoading}
          >
            <svg className="google-icon" viewBox="0 0 24 24" width="18" height="18">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"/>
              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"/>
            </svg>
            <span>{googleLoading ? 'Connecting to Google...' : 'Continue with Google'}</span>
          </button>

          {googleError && <p className="form-error google-error" role="alert">{googleError}</p>}
          {showRedirectOption && (
            <button className="secondary redirect-button" type="button" onClick={handleGoogleRedirect} disabled={googleLoading}>
              Continue with redirect
            </button>
          )}
          <p className="login-note">Secured with Google and Firebase Authentication. Messages are encrypted on-device.</p>
        </main>

        {/* Claim Handle Modal */}
        {showHandleModal && (
          <dialog className="modal" open style={{ display: 'block' }}>
            <form className="modal-content" onSubmit={handleClaimModalSubmit}>
              <p className="section-label">ONE LAST STEP</p>
              <h2>Choose your handle</h2>
              <p className="modal-copy">People will use this unique handle to send direct encrypted messages to you on DuoChat.</p>
              <input
                className="auth-input"
                value={handleModalInput}
                onChange={(e) => setHandleModalInput(e.target.value)}
                placeholder="yourname"
                required
                autoFocus
              />
              {handleModalError && <p className="form-error">{handleModalError}</p>}
              <div className="modal-actions" style={{ marginTop: 16 }}>
                <button className="primary" type="submit">Complete Setup</button>
              </div>
            </form>
          </dialog>
        )}
      </section>
    );
  }

  // Authenticated: Main Chat Application
  return (
    <div className={`chat-app ${mobileConversationOpen ? 'conversation-open' : ''}`}>
      {/* Sidebar / Inboxes */}
      <aside className="sidebar">
        <header className="sidebar-header">
          <div className="user-profile-summary">
            <div className="avatar">{currentUser.username.slice(0, 2).toUpperCase()}</div>
            <div className="user-info">
              <span className="whoami">@{currentUser.username}</span>
              <span className="user-email-tag">{currentUser.email || `@${currentUser.username}`}</span>
            </div>
          </div>
          <div className="sidebar-header-actions">
            <button className="icon-button" type="button" onClick={openNewChat} title="New Conversation">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 5v14M5 12h14"/>
              </svg>
            </button>
            <button className="icon-button" type="button" onClick={handleSignOut} title="Sign Out">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>
              </svg>
            </button>
          </div>
        </header>

        {/* Tab Navigation */}
        <div className="tab-nav">
          <button
            className={`tab-btn ${activeInboxTab === 'messages' ? 'active' : ''}`}
            type="button"
            onClick={() => setActiveInboxTab('messages')}
          >
            <span>Messages</span>
            {chats.length > 0 && <span className="tab-badge">{chats.length}</span>}
          </button>
          <button
            className={`tab-btn ${activeInboxTab === 'requests' ? 'active' : ''}`}
            type="button"
            onClick={() => setActiveInboxTab('requests')}
          >
            <span>Requests</span>
            {pendingRequests.length > 0 && <span className="tab-badge highlight">{pendingRequests.length}</span>}
          </button>
        </div>

        {/* Search */}
        <div className="search-wrap">
          <input
            className="chat-search"
            placeholder="Search conversations..."
            value={searchFilter}
            onChange={(e) => setSearchFilter(e.target.value)}
          />
        </div>

        {/* Messages Tab */}
        {activeInboxTab === 'messages' && (
          <div className="chat-list" role="list">
            {visibleChats.length === 0 ? (
              <div className="list-empty">
                <p>No conversations yet.</p>
                <button className="secondary" type="button" onClick={openNewChat} style={{ fontSize: 12, marginTop: 8 }}>
                  Start a conversation
                </button>
              </div>
            ) : (
              visibleChats.map((c) => {
                const partner = c.members.find((m) => m !== currentUser.username) || c.members[0];
                const isSelected = c.id === activeChatId;
                const timeStr = c.lastMessageTimestamp
                  ? new Date(c.lastMessageTimestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                  : '';
                return (
                  <div
                    key={c.id}
                    className={`chat-list-item ${isSelected ? 'active' : ''}`}
                    onClick={() => {
                      setActiveChatId(c.id);
                      setMobileConversationOpen(true);
                    }}
                    role="listitem"
                  >
                    <div className="avatar">{partner.slice(0, 2).toUpperCase()}</div>
                    <div className="item-body">
                      <div className="item-head">
                        <strong>@{partner}</strong>
                        {timeStr && <span className="item-time">{timeStr}</span>}
                      </div>
                      <p className="item-preview">
                        {c.lastMessage
                          ? `${c.lastMessageSender === currentUser.username ? 'You: ' : ''}${c.lastMessage}`
                          : 'Encrypted thread started'}
                      </p>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        )}

        {/* Requests Tab */}
        {activeInboxTab === 'requests' && (
          <div className="requests-list" role="list">
            {pendingRequests.length === 0 ? (
              <div className="list-empty">
                <p>No pending message requests.</p>
              </div>
            ) : (
              pendingRequests.map((req) => (
                <div key={req.id} className="request-card" role="listitem">
                  <div className="request-head">
                    <div className="avatar">{req.senderUsername.slice(0, 2).toUpperCase()}</div>
                    <div className="request-copy">
                      <strong>@{req.senderUsername}</strong>
                      <small>Sent you a private chat request</small>
                    </div>
                  </div>
                  <div className="request-actions">
                    <button className="primary" type="button" onClick={() => handleAcceptRequest(req)}>
                      Accept
                    </button>
                    <button className="secondary" type="button" onClick={() => handleDeclineRequest(req)}>
                      Decline
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </aside>

      {/* Main Conversation View */}
      <section className="conversation">
        {!activeChatId ? (
          <div className="empty-state">
            <div className="empty-state-card">
              <span className="brand-mark" style={{ margin: '0 auto 16px' }}>✳</span>
              <h2>Your Private Space</h2>
              <p>End-to-end encrypted messaging directly between two people. Messages stay strictly on-device.</p>
              <button className="primary" type="button" onClick={openNewChat}>
                Start a new conversation
              </button>
            </div>
          </div>
        ) : (
          <div className="active-chat-container">
            {/* Conversation Header */}
            <header className="chat-header">
              <button
                className="back-button"
                type="button"
                onClick={() => setMobileConversationOpen(false)}
                title="Back to inboxes"
              >
                ←
              </button>
              <div className="avatar">{partnerUsername.slice(0, 2).toUpperCase()}</div>
              <div className="chat-heading">
                <strong>@{partnerUsername}</strong>
                <span className={`chat-status ${partnerTyping ? 'typing' : 'connected'}`}>
                  {partnerTyping ? 'typing...' : 'End-to-End Encrypted'}
                </span>
              </div>
              <div className="header-actions">
                <button
                  className="delete-button text-button"
                  type="button"
                  onClick={() => setShowDeleteModal(true)}
                  title="Delete conversation"
                >
                  Delete chat
                </button>
              </div>
            </header>

            {/* Message Stream */}
            <div className="message-list">
              <div className="key-warning">
                🔒 Messages are secured with AES-GCM 256-bit on-device encryption. Only you and @{partnerUsername} hold the decryption keys.
              </div>

              {messages.map((msg) => {
                const isMine = msg.sender === currentUser.username;
                const timeStr = msg.timestamp
                  ? new Date(msg.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
                  : '';
                const partnerReadTime = chatReads[partnerUsername] || 0;
                const isRead = isMine && partnerReadTime >= msg.timestamp;

                return (
                  <div key={msg.id} className={`message-row ${isMine ? 'mine' : ''}`}>
                    <div className="message-bubble">{msg.decryptedText || msg.payload}</div>
                    <div className="message-meta">
                      <span>{timeStr}</span>
                      {isMine && (
                        <span className={`read-status ${isRead ? 'read' : 'sent'}`}>
                          <svg className="check-icon" viewBox="0 0 24 24" width="13" height="13" fill="none" strokeWidth="2.5">
                            {isRead ? (
                              <path strokeLinecap="round" strokeLinejoin="round" d="M1.5 12.5l5 5L18 6M6.5 12.5l5 5L23 6"/>
                            ) : (
                              <path strokeLinecap="round" strokeLinejoin="round" d="M3 12.5l5 5L20 6"/>
                            )}
                          </svg>
                          <span className="status-label">{isRead ? 'Read' : 'Sent'}</span>
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}

              {partnerTyping && (
                <div className="message-row">
                  <div className="message-bubble" style={{ color: 'var(--muted)', fontStyle: 'italic', display: 'flex', gap: 6, alignItems: 'center' }}>
                    <span>@{partnerUsername} is typing</span>
                    <span className="pulse-dot" style={{ width: 5, height: 5 }}></span>
                  </div>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {/* Composer */}
            <form className="composer" onSubmit={handleSendMessage}>
              <textarea
                placeholder="Type an encrypted message..."
                value={messageText}
                onChange={handleInputChange}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    handleSendMessage();
                  }
                }}
                rows={1}
              />
              <button className="primary send-button" type="submit" disabled={!messageText.trim()}>
                Send <span>↗</span>
              </button>
            </form>
          </div>
        )}
      </section>

      {/* New Conversation Modal */}
      {showNewChatModal && (
        <dialog className="modal" open style={{ display: 'block' }}>
          <div className="modal-content">
            <button className="modal-close" type="button" onClick={() => setShowNewChatModal(false)}>×</button>
            <p className="section-label">NEW CONVERSATION</p>
            <h2>Start a private thread</h2>
            <p className="modal-copy">Search registered handles on DuoChat to start an encrypted direct conversation.</p>

            <input
              className="auth-input"
              placeholder="Search by username..."
              value={userSearchTerm}
              onChange={(e) => setUserSearchTerm(e.target.value)}
              autoFocus
            />

            <div className="suggested-header" style={{ marginTop: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span>Registered Users</span>
              <button className="text-button" type="button" onClick={loadUsers}>Refresh</button>
            </div>

            <div className="suggested-users-list" role="list" style={{ marginTop: 8, maxHeight: 220, overflowY: 'auto' }}>
              {loadingUsers ? (
                <div className="list-empty">Loading users...</div>
              ) : visibleUsers.length === 0 ? (
                <div className="list-empty">No users found.</div>
              ) : (
                visibleUsers.map((u) => (
                  <div key={u.uid} className="suggested-user-item" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: '1px solid var(--line)' }}>
                    <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                      <div className="avatar" style={{ width: 34, height: 34, fontSize: 12 }}>{u.username.slice(0, 2).toUpperCase()}</div>
                      <div>
                        <strong>@{u.username}</strong>
                        {u.email && <div style={{ fontSize: 11, color: 'var(--muted)' }}>{u.email}</div>}
                      </div>
                    </div>
                    <button className="primary" type="button" onClick={() => handleStartChatWithUser(u)} style={{ minHeight: 32, fontSize: 12, padding: '0 12px' }}>
                      Chat
                    </button>
                  </div>
                ))
              )}
            </div>

            {newChatError && <p className="form-error">{newChatError}</p>}
          </div>
        </dialog>
      )}

      {/* Delete Chat Dialog */}
      {showDeleteModal && (
        <dialog className="modal" open style={{ display: 'block' }}>
          <div className="modal-content">
            <button className="modal-close" type="button" onClick={() => setShowDeleteModal(false)}>×</button>
            <p className="section-label">A CLEAN BREAK</p>
            <h2>Delete this chat?</h2>
            <p className="modal-copy">This removes the conversation and its messages for both people. There is no undo button.</p>
            <div className="modal-actions" style={{ display: 'flex', gap: 10, marginTop: 20 }}>
              <button className="secondary" type="button" onClick={() => setShowDeleteModal(false)}>Keep it</button>
              <button className="danger-button" type="button" onClick={handleDeleteChat}>Delete for both</button>
            </div>
          </div>
        </dialog>
      )}

      {/* Toast Notification */}
      {toastMessage && (
        <div className="toast" role="status">
          {toastMessage}
        </div>
      )}
    </div>
  );
}
