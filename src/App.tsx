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
  deleteFirestoreChat,
  createRoomInvite,
  getRoomInvite,
  subscribeToRoomInvite,
  acceptRoomInvite,
  cancelRoomInvite
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

interface RoomInvite {
  code: string;
  creatorUid: string;
  creatorUsername: string;
  chatId: string;
  chatKey: string;
  expiresAt: number;
  status: 'pending' | 'accepted' | 'cancelled';
  acceptedByUsername?: string;
}

interface EmojiItem {
  emoji: string;
  shortcode: string;
  keywords: string;
}

// 42 Curated Emojis from DuoChat
const EMOJI_CATALOG: EmojiItem[] = [
  ["😀", "grinning", "smile happy face"],
  ["😃", "smiley", "happy face"],
  ["😂", "joy", "laugh cry"],
  ["🤣", "rofl", "laugh rolling"],
  ["😊", "blush", "smile happy"],
  ["😍", "heart_eyes", "love"],
  ["🥰", "smiling_face_with_hearts", "love affection"],
  ["😘", "kissing_heart", "kiss love"],
  ["😎", "sunglasses", "cool"],
  ["🤔", "thinking", "think question"],
  ["🙄", "roll_eyes", "eyeroll"],
  ["🥲", "smiling_face_with_tear", "happy sad"],
  ["😭", "sob", "cry sad"],
  ["😡", "rage", "angry"],
  ["🤯", "exploding_head", "mind blown"],
  ["👀", "eyes", "look see"],
  ["👍", "thumbsup", "yes good"],
  ["👎", "thumbsdown", "no bad"],
  ["🙌", "raised_hands", "celebrate praise"],
  ["👏", "clap", "applause"],
  ["🙏", "pray", "please thanks"],
  ["💀", "skull", "dead funny"],
  ["🔥", "fire", "hot lit"],
  ["✨", "sparkles", "magic shiny"],
  ["❤️", "heart", "love red"],
  ["💔", "broken_heart", "sad heartbreak"],
  ["💯", "100", "perfect score"],
  ["🎉", "tada", "party celebrate"],
  ["✅", "white_check_mark", "done yes"],
  ["🤝", "handshake", "deal"],
  ["🫡", "saluting_face", "salute respect"],
  ["🤷", "shrug", "dunno"],
  ["🤦", "facepalm", "oops"],
  ["🐈", "cat", "pet animal"],
  ["🐶", "dog", "pet animal"],
  ["🍕", "pizza", "food"],
  ["🍿", "popcorn", "snack movie"],
  ["☕", "coffee", "tea drink"],
  ["🌮", "taco", "food"],
  ["🚀", "rocket", "launch space"],
  ["🌈", "rainbow", "color"],
  ["💤", "zzz", "sleep tired"]
].map(([emoji, shortcode, keywords]) => ({ emoji, shortcode, keywords }));

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

function formatDuration(ms: number) {
  const total = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor((total % 3600) / 60);
  const seconds = total % 60;
  const two = (n: number) => String(n).padStart(2, '0');
  return `${two(minutes)}:${two(seconds)}`;
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
  const [hasCryptoKey, setHasCryptoKey] = useState(true);
  const [partnerTyping, setPartnerTyping] = useState(false);
  const [chatReads, setChatReads] = useState<{ [username: string]: number }>({});

  // Direct Message Requests State
  const [pendingRequests, setPendingRequests] = useState<ChatRequest[]>([]);

  // 12-Digit Room Invite State
  const [activeInvite, setActiveInvite] = useState<RoomInvite | null>(null);
  const [inviteTimeRemaining, setInviteTimeRemaining] = useState<number>(0);
  const [showInviteModal, setShowInviteModal] = useState(false);

  // Join Room with Number Modal State
  const [showJoinModal, setShowJoinModal] = useState(false);
  const [joinCodeInput, setJoinCodeInput] = useState('');
  const [joinKeyInput, setJoinKeyInput] = useState('');
  const [joinError, setJoinError] = useState('');
  const [joiningChat, setJoiningChat] = useState(false);

  // New Chat User Discovery Modal State
  const [showNewChatModal, setShowNewChatModal] = useState(false);
  const [registeredUsers, setRegisteredUsers] = useState<RegisteredUser[]>([]);
  const [userSearchTerm, setUserSearchTerm] = useState('');
  const [loadingUsers, setLoadingUsers] = useState(false);
  const [newChatError, setNewChatError] = useState('');

  // Choose Username / Handle Modal State
  const [showHandleModal, setShowHandleModal] = useState(false);
  const [handleModalInput, setHandleModalInput] = useState('');
  const [handleModalError, setHandleModalError] = useState('');
  const [pendingGoogleUser, setPendingGoogleUser] = useState<any>(null);

  // Modals & Feedback
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [toastMessage, setToastMessage] = useState('');

  // Emoji Suggestions State
  const [emojiQuery, setEmojiQuery] = useState<{ query: string; startIndex: number } | null>(null);
  const [activeEmojiIndex, setActiveEmojiIndex] = useState(0);

  // Refs
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const typingTimeoutRef = useRef<any>(null);
  const isTypingRef = useRef(false);

  // Toast Helper
  const showToast = useCallback((msg: string) => {
    setToastMessage(msg);
    setTimeout(() => {
      setToastMessage((prev) => (prev === msg ? '' : prev));
    }, 3200);
  }, []);

  // Filtered Emoji Suggestions
  const matchingEmojis = useMemo(() => {
    if (!emojiQuery) return [];
    const q = emojiQuery.query.toLowerCase();
    return EMOJI_CATALOG.filter((item) =>
      item.shortcode.toLowerCase().includes(q) || item.keywords.toLowerCase().includes(q)
    ).slice(0, 7);
  }, [emojiQuery]);

  // Read URL parameters and fragment for invites (#key=... or ?invite=...)
  const checkUrlInvite = useCallback(() => {
    try {
      const urlParams = new URLSearchParams(window.location.search);
      const hash = window.location.hash.startsWith('#') ? window.location.hash.slice(1) : window.location.hash;
      const hashParams = new URLSearchParams(hash);

      const code = urlParams.get('invite') || hashParams.get('code') || '';
      const key = hashParams.get('key') || urlParams.get('key') || '';

      if (code) {
        setJoinCodeInput(code.replace(/\D/g, '').slice(0, 12));
      }
      if (key) {
        setJoinKeyInput(key);
      }
      if (code || key) {
        setShowJoinModal(true);
      }
    } catch (e) {
      console.warn('Could not parse URL invite:', e);
    }
  }, []);

  // Sync Auth State & Redirect Results
  useEffect(() => {
    let unsubscribeProfile: (() => void) | null = null;

    getRedirectResult(auth)
      .then(async (result) => {
        if (result && result.user) {
          await handleAuthSuccess(result.user);
        }
      })
      .catch((err) => {
        console.warn('Redirect sign in error:', err);
      });

    const unsubscribeAuth = onAuthStateChanged(auth, async (user) => {
      if (user) {
        await handleAuthSuccess(user);
      } else {
        const savedDemo = sessionStorage.getItem('duochat_demo_user');
        if (savedDemo) {
          try {
            const parsed = JSON.parse(savedDemo);
            setCurrentUser(parsed);
          } catch {
            setCurrentUser(null);
          }
        } else {
          setCurrentUser(null);
        }
        setAuthLoading(false);
      }
    });

    return () => {
      unsubscribeAuth();
    };
  }, []);

  // Check URL invite once on mount
  useEffect(() => {
    checkUrlInvite();
  }, [checkUrlInvite]);

  // Handle successful login
  const handleAuthSuccess = async (user: any) => {
    try {
      const profile = await getUserProfile(user.uid);
      if (!profile || !profile.username) {
        setPendingGoogleUser(user);
        const suggested = (user.displayName || user.email?.split('@')[0] || 'user')
          .toLowerCase()
          .replace(/[^a-z0-9_]/g, '')
          .slice(0, 18);
        setHandleModalInput(suggested);
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
    } catch (err: any) {
      console.error('Error fetching profile:', err);
      setAuthLoading(false);
    }
  };

  // Google Sign In (Popup with Redirect Fallback)
  const handleGoogleSignIn = async () => {
    setGoogleLoading(true);
    setGoogleError('');
    setShowRedirectOption(false);
    try {
      const result = await signInWithPopup(auth, googleProvider);
      if (result.user) {
        await handleAuthSuccess(result.user);
      }
    } catch (err: any) {
      console.error('Google Sign In Error:', err);
      if (err.code === 'auth/popup-blocked' || err.code === 'auth/cancelled-popup-request') {
        setGoogleError('Popup was blocked by your browser. You can continue using direct redirect.');
        setShowRedirectOption(true);
      } else if (err.code === 'auth/unauthorized-domain') {
        setGoogleError(
          `Domain not authorized in Firebase Auth. Ensure your current domain is added in Firebase Console > Authentication > Settings > Authorized Domains.`
        );
      } else {
        setGoogleError(err.message || 'Unable to sign in with Google.');
      }
    } finally {
      setGoogleLoading(false);
    }
  };

  const handleGoogleRedirect = async () => {
    setGoogleLoading(true);
    setGoogleError('');
    try {
      await signInWithRedirect(auth, googleProvider);
    } catch (err: any) {
      setGoogleError(err.message || 'Unable to redirect.');
      setGoogleLoading(false);
    }
  };

  // 1-Click Instant Demo Login (Zero friction testing)
  const handleDemoSignIn = async () => {
    const randomSuffix = Math.floor(1000 + Math.random() * 9000);
    const demoHandle = `tester_${randomSuffix}`;
    const demoUser: UserProfile = {
      uid: `demo_${demoHandle}`,
      username: demoHandle,
      email: `${demoHandle}@duochat.local`,
      displayName: `Tester ${randomSuffix}`
    };
    try {
      await claimUsername(demoUser.uid, demoHandle, demoUser.email);
    } catch (e) {
      console.warn('Demo claim note:', e);
    }
    sessionStorage.setItem('duochat_demo_user', JSON.stringify(demoUser));
    setCurrentUser(demoUser);
    showToast(`Signed in as @${demoHandle}`);
  };

  // Sign Out
  const handleSignOut = async () => {
    sessionStorage.removeItem('duochat_demo_user');
    await fbSignOut(auth).catch(() => {});
    setCurrentUser(null);
    setChats([]);
    setActiveChatId('');
    setMessages([]);
    showToast('Signed out.');
  };

  // Claim Unique Handle Modal
  const handleClaimModalSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!pendingGoogleUser) return;
    const cleanHandle = handleModalInput.trim().toLowerCase();
    if (!/^[a-z0-9_]{3,24}$/.test(cleanHandle)) {
      setHandleModalError('Handle must be 3-24 characters: letters, numbers, and underscores.');
      return;
    }
    setHandleModalError('');
    try {
      await claimUsername(pendingGoogleUser.uid, cleanHandle, pendingGoogleUser.email);
      setCurrentUser({
        uid: pendingGoogleUser.uid,
        email: pendingGoogleUser.email,
        displayName: pendingGoogleUser.displayName || cleanHandle,
        username: cleanHandle
      });
      setShowHandleModal(false);
      setPendingGoogleUser(null);
      showToast(`Welcome to DuoChat, @${cleanHandle}!`);
    } catch (err: any) {
      setHandleModalError(err.message || 'That handle is already taken. Try another.');
    }
  };

  // Real-Time Subscriptions: Chats & Incoming Requests
  useEffect(() => {
    if (!currentUser?.username) return;

    const unsubChats = subscribeToUserChats(currentUser.username, (loadedChats: Chat[]) => {
      setChats(loadedChats);
      if (activeChatId && !loadedChats.some((c: Chat) => c.id === activeChatId)) {
        // Chat was deleted by the other person
        setActiveChatId('');
        setMobileConversationOpen(false);
        showToast('This conversation was closed.');
      }
    });

    const unsubRequests = subscribeToIncomingRequests(currentUser.username, (requests: ChatRequest[]) => {
      setPendingRequests(requests);
    });

    return () => {
      unsubChats();
      unsubRequests();
    };
  }, [currentUser?.username, activeChatId, showToast]);

  // Active Chat Encryption Key & Message Subscriptions
  useEffect(() => {
    if (!activeChatId || !currentUser?.username) {
      setCryptoKey(null);
      setMessages([]);
      return;
    }

    let unsubMessages = () => {};
    let unsubReads = () => {};
    let unsubTyping = () => {};

    const loadKeyAndMessages = async () => {
      try {
        const storedKey = localStorage.getItem(`${CHAT_KEY_PREFIX}${activeChatId}`);
        let keyBase64 = storedKey;

        if (!keyBase64) {
          keyBase64 = await getPersistentChatKey(activeChatId, currentUser.uid);
          if (keyBase64) {
            localStorage.setItem(`${CHAT_KEY_PREFIX}${activeChatId}`, keyBase64);
          }
        }

        if (keyBase64) {
          const key = await importChatKey(keyBase64);
          setCryptoKey(key);
          setHasCryptoKey(true);

          unsubMessages = subscribeToChatMessages(activeChatId, async (newMsg: any) => {
            const decrypted = await decryptMessage(key, newMsg.text);
            const msgObj: Message = {
              id: newMsg.id,
              chatId: activeChatId,
              sender: newMsg.sender,
              payload: newMsg.text,
              decryptedText: decrypted,
              timestamp: newMsg.ts
            };
            setMessages((prev) => {
              if (prev.some((m) => m.id === msgObj.id)) return prev;
              return [...prev, msgObj].sort((a, b) => a.timestamp - b.timestamp);
            });
            setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 60);
          });
        } else {
          setHasCryptoKey(false);
          setCryptoKey(null);
        }

        await recordChatOpened(activeChatId, currentUser.username);

        unsubReads = subscribeToChatReads(activeChatId, (reads: { [username: string]: number }) => {
          setChatReads(reads);
        });

        unsubTyping = subscribeToChatTyping(activeChatId, (typingUsers: { [username: string]: boolean }) => {
          const activeChatObj = chats.find((c) => c.id === activeChatId);
          if (!activeChatObj) return;
          const other = activeChatObj.members.find((m) => m !== currentUser.username);
          if (other && typingUsers[other]) {
            setPartnerTyping(true);
          } else {
            setPartnerTyping(false);
          }
        });
      } catch (err) {
        console.error('Failed to set up chat session:', err);
      }
    };

    loadKeyAndMessages();

    return () => {
      unsubMessages();
      unsubReads();
      unsubTyping();
    };
  }, [activeChatId, currentUser?.username, currentUser?.uid, chats]);

  // Room Invite Countdown Timer
  useEffect(() => {
    if (!activeInvite || activeInvite.status !== 'pending') return;

    const tick = () => {
      const remaining = activeInvite.expiresAt - Date.now();
      if (remaining <= 0) {
        setInviteTimeRemaining(0);
        showToast('Invite expired.');
        setActiveInvite(null);
        setShowInviteModal(false);
      } else {
        setInviteTimeRemaining(remaining);
      }
    };

    tick();
    const interval = setInterval(tick, 1000);
    return () => clearInterval(interval);
  }, [activeInvite, showToast]);

  // Real-Time Listener on Created Room Invite
  useEffect(() => {
    if (!activeInvite?.code || !currentUser?.username) return;

    const unsub = subscribeToRoomInvite(activeInvite.code, async (updatedInvite: any) => {
      if (!updatedInvite) return;
      if (updatedInvite.status === 'accepted') {
        const partner = updatedInvite.acceptedByUsername || 'friend';
        showToast(`@${partner} accepted your invite!`);
        setShowInviteModal(false);
        setActiveInvite(null);

        // Open chat immediately
        setActiveInboxTab('messages');
        setActiveChatId(updatedInvite.chatId);
        setMobileConversationOpen(true);
      }
    });

    return () => unsub();
  }, [activeInvite?.code, currentUser?.username, showToast]);

  // CREATE 12-DIGIT ROOM INVITE
  const handleStartInvite = async () => {
    if (!currentUser?.username) return;
    try {
      const codeNumber = Math.floor(100000000000 + Math.random() * 900000000000).toString();
      const keyText = await generateChatKey();
      const chatId = `duo_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
      const expiresAt = Date.now() + 15 * 60 * 1000; // 15 mins

      // Save key locally and to Firestore for creator
      localStorage.setItem(`${CHAT_KEY_PREFIX}${chatId}`, keyText);
      await savePersistentChatKey(chatId, currentUser.uid, keyText);

      // Create initial chat placeholder
      const chat: Chat = {
        id: chatId,
        members: [currentUser.username],
        createdAt: Date.now(),
        updatedAt: Date.now()
      };
      await saveFirestoreChat(chat);

      // Save Room Invite record
      const inviteData: RoomInvite = {
        code: codeNumber,
        creatorUid: currentUser.uid,
        creatorUsername: currentUser.username,
        chatId,
        chatKey: keyText,
        expiresAt,
        status: 'pending'
      };
      await createRoomInvite(inviteData);

      setActiveInvite(inviteData);
      setShowInviteModal(true);
    } catch (err: any) {
      showToast(err.message || 'Could not create invite.');
    }
  };

  // CANCEL ROOM INVITE
  const handleCancelInvite = async () => {
    if (!activeInvite) return;
    try {
      await cancelRoomInvite(activeInvite.code);
      setActiveInvite(null);
      setShowInviteModal(false);
      showToast('Invite cancelled.');
    } catch (err: any) {
      showToast(err.message || 'Could not cancel invite.');
    }
  };

  // ACCEPT INVITE BY 12-DIGIT NUMBER & KEY
  const handleJoinByInviteSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!currentUser?.username) return;
    setJoinError('');
    setJoiningChat(true);

    const cleanCode = joinCodeInput.replace(/\D/g, '').trim();
    const cleanKey = joinKeyInput.trim();

    if (cleanCode.length !== 12) {
      setJoinError('Please enter a valid 12-digit invite number.');
      setJoiningChat(false);
      return;
    }
    if (!cleanKey) {
      setJoinError('Please provide the encryption key.');
      setJoiningChat(false);
      return;
    }

    try {
      // Validate key length
      await importChatKey(cleanKey);

      const invite = await acceptRoomInvite(cleanCode, currentUser.uid, currentUser.username);
      if (!invite) throw new Error('Invite not found.');

      // Save key locally and in Firestore for current user
      localStorage.setItem(`${CHAT_KEY_PREFIX}${invite.chatId}`, cleanKey);
      await savePersistentChatKey(invite.chatId, currentUser.uid, cleanKey);

      // Update members in chat
      const chat: Chat = {
        id: invite.chatId,
        members: [invite.creatorUsername, currentUser.username],
        updatedAt: Date.now()
      };
      await saveFirestoreChat(chat);

      setShowJoinModal(false);
      setJoinCodeInput('');
      setJoinKeyInput('');
      setActiveInboxTab('messages');
      setActiveChatId(invite.chatId);
      setMobileConversationOpen(true);
      showToast(`Connected with @${invite.creatorUsername}!`);
    } catch (err: any) {
      setJoinError(err.message || 'Unable to join invite.');
    } finally {
      setJoiningChat(false);
    }
  };

  // Send Message
  const handleSendMessage = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const text = messageText.trim();
    if (!text || !activeChatId || !currentUser?.username || !cryptoKey) return;

    setMessageText('');
    setEmojiQuery(null);

    // Stop typing status
    if (isTypingRef.current) {
      isTypingRef.current = false;
      await recordUserTyping(activeChatId, currentUser.username, false);
    }

    try {
      const encrypted = await encryptMessage(cryptoKey, text);
      const tempId = `msg_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`;
      const msg: Message = {
        id: tempId,
        chatId: activeChatId,
        sender: currentUser.username,
        payload: encrypted,
        decryptedText: text,
        timestamp: Date.now()
      };

      setMessages((prev) => [...prev, msg]);
      setTimeout(() => messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);

      await saveFirestoreMessage(activeChatId, {
        id: tempId,
        sender: currentUser.username,
        text: encrypted,
        ts: Date.now()
      });
    } catch (err: any) {
      console.error('Send error:', err);
      showToast('Could not send encrypted message.');
    }
  };

  // Textarea input and Emoji Autocomplete Detection
  const handleInputChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const val = e.target.value;
    const caret = e.target.selectionStart;
    setMessageText(val);

    // Detect :emoji query
    const beforeCaret = val.slice(0, caret);
    const colonMatch = beforeCaret.match(/:([a-zA-Z0-9_]{1,15})$/);
    if (colonMatch) {
      setEmojiQuery({
        query: colonMatch[1],
        startIndex: caret - colonMatch[0].length
      });
      setActiveEmojiIndex(0);
    } else {
      setEmojiQuery(null);
    }

    // Typing debouncing
    if (activeChatId && currentUser?.username) {
      if (!isTypingRef.current) {
        isTypingRef.current = true;
        recordUserTyping(activeChatId, currentUser.username, true);
      }
      clearTimeout(typingTimeoutRef.current);
      typingTimeoutRef.current = setTimeout(() => {
        isTypingRef.current = false;
        recordUserTyping(activeChatId, currentUser.username, false);
      }, 2500);
    }
  };

  // Insert Emoji from Autocomplete
  const insertSelectedEmoji = (item: EmojiItem) => {
    if (!emojiQuery || !textareaRef.current) return;
    const { startIndex } = emojiQuery;
    const before = messageText.slice(0, startIndex);
    const caret = textareaRef.current.selectionStart;
    const after = messageText.slice(caret);
    const newText = `${before}${item.emoji} ${after}`;
    setMessageText(newText);
    setEmojiQuery(null);
    setTimeout(() => {
      if (textareaRef.current) {
        const newPos = before.length + item.emoji.length + 1;
        textareaRef.current.focus();
        textareaRef.current.setSelectionRange(newPos, newPos);
      }
    }, 10);
  };

  // Handle Keys in Composer
  const handleComposerKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (emojiQuery && matchingEmojis.length > 0) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActiveEmojiIndex((prev) => (prev + 1) % matchingEmojis.length);
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActiveEmojiIndex((prev) => (prev - 1 + matchingEmojis.length) % matchingEmojis.length);
        return;
      }
      if (e.key === 'Enter' || e.key === 'Tab') {
        e.preventDefault();
        insertSelectedEmoji(matchingEmojis[activeEmojiIndex]);
        return;
      }
      if (e.key === 'Escape') {
        e.preventDefault();
        setEmojiQuery(null);
        return;
      }
    }

    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  // Copy helper
  const copyTextToClipboard = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      showToast(`Copied ${label} to clipboard`);
    } catch {
      showToast('Clipboard access unavailable.');
    }
  };

  // User Discovery / New Chat
  const loadUsers = async () => {
    setLoadingUsers(true);
    try {
      const list = await getAllRegisteredUsers();
      setRegisteredUsers(list.filter((u) => u.username !== currentUser?.username));
    } catch (err: any) {
      setNewChatError(err.message || 'Could not load users.');
    } finally {
      setLoadingUsers(false);
    }
  };

  const openNewChat = () => {
    setNewChatError('');
    setUserSearchTerm('');
    setShowNewChatModal(true);
    loadUsers();
  };

  const handleStartChatWithUser = async (user: RegisteredUser) => {
    if (!currentUser?.username) return;
    try {
      const existing = chats.find((c) => c.members.includes(user.username));
      if (existing) {
        setShowNewChatModal(false);
        setActiveChatId(existing.id);
        setMobileConversationOpen(true);
        return;
      }

      const keyText = await generateChatKey();
      const chatId = `dm_${[currentUser.username, user.username].sort().join('_')}`;

      localStorage.setItem(`${CHAT_KEY_PREFIX}${chatId}`, keyText);
      await savePersistentChatKey(chatId, currentUser.uid, keyText);

      await sendDirectChatRequest({
        senderUid: currentUser.uid,
        senderUsername: currentUser.username,
        recipientUid: user.uid,
        recipientUsername: user.username,
        chatId,
        chatKey: keyText
      });

      setShowNewChatModal(false);
      showToast(`Encrypted request sent to @${user.username}`);
    } catch (err: any) {
      setNewChatError(err.message || 'Failed to start conversation.');
    }
  };

  // Accept DM request
  const handleAcceptRequest = async (req: ChatRequest) => {
    if (!currentUser?.username) return;
    try {
      await acceptDirectChatRequest(req.id);
      localStorage.setItem(`${CHAT_KEY_PREFIX}${req.chatId}`, req.chatKey);
      await savePersistentChatKey(req.chatId, currentUser.uid, req.chatKey);

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
      showToast('Conversation deleted for both people.');
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

  // Filtered chats (by partner username or preview)
  const visibleChats = useMemo(() => {
    if (!currentUser?.username) return [];
    const term = searchFilter.trim().toLowerCase();
    return chats.filter((c) => {
      const partner = c.members.find((m) => m !== currentUser.username) || '';
      const preview = c.lastMessage || '';
      return partner.toLowerCase().includes(term) || preview.toLowerCase().includes(term);
    });
  }, [chats, searchFilter, currentUser?.username]);

  // Filtered registered users
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
          <p style={{ letterSpacing: '0.1em', fontSize: 13, textTransform: 'uppercase' }}>Connecting to DuoChat...</p>
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

          {/* Primary Google Sign In */}
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

          {googleError && <p className="google-error" role="alert">{googleError}</p>}
          {showRedirectOption && (
            <button className="secondary redirect-button" type="button" onClick={handleGoogleRedirect} disabled={googleLoading}>
              Continue with redirect
            </button>
          )}

          {/* Quick Demo Test Option */}
          <div className="demo-login-divider"><span>or explore instant demo</span></div>
          <button className="demo-auth-button" type="button" onClick={handleDemoSignIn}>
            <span>⚡ Instant Demo Account</span>
          </button>

          <p className="login-note">Secured with Firebase Authentication & on-device AES-GCM 256-bit encryption.</p>
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
      {/* Sidebar */}
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
            <button className="icon-button" type="button" onClick={openNewChat} title="Search users">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8"/>
                <line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
            </button>
            <button className="icon-button" type="button" onClick={handleSignOut} title="Sign Out">
              <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9"/>
              </svg>
            </button>
          </div>
        </header>

        {/* Action Buttons: Start Invite & Join with Number */}
        <div className="sidebar-action-buttons">
          <button className="primary" type="button" onClick={handleStartInvite} title="Create private 12-digit invite">
            + Start an invite
          </button>
          <button className="secondary" type="button" onClick={() => { setJoinError(''); setShowJoinModal(true); }} title="Join an invite using number">
            Join with number
          </button>
        </div>

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
          <svg viewBox="0 0 24 24">
            <circle cx="11" cy="11" r="7"/>
            <line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input
            placeholder="Search chats or messages..."
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
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 10 }}>
                  <button className="primary" type="button" onClick={handleStartInvite} style={{ fontSize: 11, minHeight: 32 }}>
                    Start an invite
                  </button>
                  <button className="secondary" type="button" onClick={openNewChat} style={{ fontSize: 11, minHeight: 32 }}>
                    Find user handle
                  </button>
                </div>
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

        {/* Sidebar Footer */}
        <div className="sidebar-foot">
          <span>SIGNED IN AS</span>
          <strong>@{currentUser.username}</strong>
          <div className="secure-label">
            <i></i>
            <span>End-to-End Encrypted</span>
          </div>
        </div>
      </aside>

      {/* Main Conversation View */}
      <section className="conversation">
        {!activeChatId ? (
          <div className="empty-state">
            <div className="empty-content">
              <div className="empty-mark">✳</div>
              <p className="eyebrow">A PRIVATE CORNER FOR TWO</p>
              <h2>Very exclusive.<br />Two seats.</h2>
              <p>Start an invite, then wait for the other person to say yes. The room does not exist until they accept.</p>
              <div className="empty-actions">
                <button className="primary" type="button" onClick={handleStartInvite}>
                  + Start an invite
                </button>
                <button className="secondary" type="button" onClick={() => { setJoinError(''); setShowJoinModal(true); }}>
                  Join with number
                </button>
              </div>
              <span className="empty-note">🔒 Messages are encrypted on-device. No plain text touches the server.</span>
            </div>
          </div>
        ) : (
          <div className="active-chat">
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
              <div className="header-actions" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <button
                  className="icon-button invite-button"
                  type="button"
                  onClick={async () => {
                    const key = localStorage.getItem(`${CHAT_KEY_PREFIX}${activeChatId}`);
                    if (key) {
                      const link = `${window.location.origin}${window.location.pathname}#key=${encodeURIComponent(key)}`;
                      await copyTextToClipboard(link, 'Secure invite link');
                    } else {
                      showToast('Encryption key unavailable.');
                    }
                  }}
                  title="Copy room link & key"
                >
                  Share
                </button>
                <button
                  className="text-button delete-button"
                  type="button"
                  onClick={() => setShowDeleteModal(true)}
                  title="Delete conversation for both"
                >
                  Delete
                </button>
              </div>
            </header>

            {/* Message Stream */}
            <div className="message-list">
              {!hasCryptoKey ? (
                <div className="key-warning">
                  ⚠️ This device does not hold the encryption key for this chat. Ask your friend to share the room link.
                </div>
              ) : (
                <div className="key-warning">
                  🔒 Messages are encrypted with AES-GCM 256-bit on-device encryption. Only you and @{partnerUsername} can read them.
                </div>
              )}

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
                  <div className="message-bubble" style={{ color: 'var(--muted)', display: 'flex', gap: 6, alignItems: 'center' }}>
                    <span>@{partnerUsername} is typing</span>
                    <span className="pulse-dot" style={{ width: 6, height: 6 }}></span>
                  </div>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {/* Composer with Emoji Suggestions */}
            <div className="composer-wrapper">
              {/* Emoji Suggestions Panel */}
              {matchingEmojis.length > 0 && (
                <div className="emoji-suggestions" role="listbox" aria-label="Emoji suggestions">
                  {matchingEmojis.map((item, idx) => (
                    <button
                      key={item.shortcode}
                      className={`emoji-option ${idx === activeEmojiIndex ? 'selected' : ''}`}
                      type="button"
                      onClick={() => insertSelectedEmoji(item)}
                    >
                      <span className="emoji-glyph">{item.emoji}</span>
                      <span className="emoji-name">{item.shortcode}</span>
                      <span className="emoji-shortcode">:{item.shortcode}:</span>
                    </button>
                  ))}
                </div>
              )}

              <form className="composer" onSubmit={handleSendMessage}>
                <textarea
                  ref={textareaRef}
                  placeholder="Type an encrypted message... (type : for emoji)"
                  value={messageText}
                  onChange={handleInputChange}
                  onKeyDown={handleComposerKeyDown}
                  rows={1}
                />
                <button className="primary send-button" type="submit" disabled={!messageText.trim()}>
                  Send <span>↗</span>
                </button>
              </form>
            </div>
          </div>
        )}
      </section>

      {/* 12-Digit Room Invite Modal */}
      {showInviteModal && activeInvite && (
        <dialog className="modal" open style={{ display: 'block' }}>
          <div className="modal-content">
            <button className="modal-close" type="button" onClick={() => setShowInviteModal(false)}>×</button>
            <p className="section-label">EXCLUSIVE ROOM</p>
            <h2>Your Private Invite</h2>
            <p className="modal-copy">Give this 12-digit number to your friend, or send the secure link. The room will be created the moment they accept.</p>

            <div className="invite-code">
              {activeInvite.code.replace(/(\d{4})/g, '$1 ').trim()}
            </div>
            <p className="invite-expiry">
              Expires in {formatDuration(inviteTimeRemaining)} · one yes, one new chat
            </p>

            <input
              className="invite-link"
              readOnly
              value={`${window.location.origin}${window.location.pathname}?invite=${activeInvite.code}#key=${encodeURIComponent(activeInvite.chatKey)}`}
              onClick={(e) => (e.target as HTMLInputElement).select()}
            />

            <div className="modal-actions">
              <button
                className="secondary"
                type="button"
                onClick={() => copyTextToClipboard(activeInvite.code, 'Invite number')}
              >
                Copy number
              </button>
              <button
                className="primary"
                type="button"
                onClick={() =>
                  copyTextToClipboard(
                    `${window.location.origin}${window.location.pathname}?invite=${activeInvite.code}#key=${encodeURIComponent(activeInvite.chatKey)}`,
                    'Secure invite link'
                  )
                }
              >
                Copy secure link
              </button>
            </div>

            <div className="waiting-state">
              <span className="pulse-dot"></span>
              <span>Invite sent. Your chat is practicing its hello. Waiting for your friend to accept...</span>
            </div>

            <button className="cancel-invite" type="button" onClick={handleCancelInvite}>
              Cancel invite
            </button>
          </div>
        </dialog>
      )}

      {/* Accept Invite / Join with Number Modal */}
      {showJoinModal && (
        <dialog className="modal" open style={{ display: 'block' }}>
          <form className="modal-content" onSubmit={handleJoinByInviteSubmit}>
            <button className="modal-close" type="button" onClick={() => setShowJoinModal(false)}>×</button>
            <p className="section-label">ACCEPT AN INVITE</p>
            <h2>Join with number</h2>
            <p className="modal-copy">Enter the 12-digit number and encryption key. The private room is created when you accept.</p>

            <div className="modal-field">
              <label style={{ display: 'block', fontSize: 11, color: 'var(--muted)', marginBottom: 6 }}>12-Digit Invite Number</label>
              <input
                className="auth-input code-input"
                inputMode="numeric"
                maxLength={14}
                placeholder="0000 0000 0000"
                value={joinCodeInput}
                onChange={(e) => setJoinCodeInput(e.target.value)}
                required
              />
            </div>

            <div className="modal-field" style={{ marginTop: 12 }}>
              <label style={{ display: 'block', fontSize: 11, color: 'var(--muted)', marginBottom: 6 }}>Encryption Key</label>
              <input
                className="auth-input"
                placeholder="Paste key from secure link"
                value={joinKeyInput}
                onChange={(e) => setJoinKeyInput(e.target.value)}
                required
              />
            </div>

            {joinError && <p className="form-error" style={{ marginTop: 12 }}>{joinError}</p>}

            <div className="modal-actions" style={{ marginTop: 20 }}>
              <button className="secondary" type="button" onClick={() => setShowJoinModal(false)}>
                Cancel
              </button>
              <button className="primary" type="submit" disabled={joiningChat}>
                {joiningChat ? 'Connecting...' : 'Accept invite'}
              </button>
            </div>
          </form>
        </dialog>
      )}

      {/* New Conversation Modal (Search Users) */}
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

            <div style={{ marginTop: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 11, color: 'var(--muted)', fontWeight: 600 }}>REGISTERED USERS</span>
              <button className="text-button" type="button" onClick={loadUsers} style={{ fontSize: 11 }}>Refresh</button>
            </div>

            <div style={{ marginTop: 8, maxHeight: 220, overflowY: 'auto' }} role="list">
              {loadingUsers ? (
                <div className="list-empty">Loading users...</div>
              ) : visibleUsers.length === 0 ? (
                <div className="list-empty">No users found.</div>
              ) : (
                visibleUsers.map((u) => (
                  <div
                    key={u.uid}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '10px 0',
                      borderBottom: '1px solid var(--line)'
                    }}
                    role="listitem"
                  >
                    <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                      <div className="avatar" style={{ width: 34, height: 34, fontSize: 12 }}>
                        {u.username.slice(0, 2).toUpperCase()}
                      </div>
                      <div>
                        <strong>@{u.username}</strong>
                        {u.email && <div style={{ fontSize: 11, color: 'var(--muted)' }}>{u.email}</div>}
                      </div>
                    </div>
                    <button
                      className="primary"
                      type="button"
                      onClick={() => handleStartChatWithUser(u)}
                      style={{ minHeight: 32, fontSize: 11, padding: '0 12px' }}
                    >
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
