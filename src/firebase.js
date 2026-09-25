import { initializeApp, getApps, getApp } from "firebase/app";
import { 
  getAuth, 
  GoogleAuthProvider, 
  signInWithPopup, 
  signInWithRedirect,
  getRedirectResult,
  createUserWithEmailAndPassword, 
  signInWithEmailAndPassword, 
  signOut as fbSignOut, 
  onAuthStateChanged,
  updateProfile
} from "firebase/auth";
import { 
  getFirestore, 
  doc, 
  getDoc, 
  setDoc, 
  getDocFromServer,
  collection,
  onSnapshot,
  query,
  where,
  getDocs,
  deleteDoc
} from "firebase/firestore";
import firebaseConfig from "../firebase-applet-config.json";

// Initialize Firebase App
export const app = !getApps().length ? initializeApp(firebaseConfig) : getApp();
export const auth = getAuth(app);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const googleProvider = new GoogleAuthProvider();
googleProvider.setCustomParameters({ prompt: "select_account" });

// Validate server connectivity as required by Firestore guidelines
export async function testFirestoreConnection() {
  try {
    await getDocFromServer(doc(db, "test", "connection"));
  } catch (error) {
    if (error instanceof Error && error.message.includes("the client is offline")) {
      console.warn("Firestore connection check: client is offline or network restricted.");
    }
  }
}
testFirestoreConnection();

/**
 * Get or register the username handle associated with the Firebase user.
 * Each username is unique in the usernames collection.
 */
export async function getUserProfile(uid) {
  if (!uid) return null;
  try {
    const userDoc = await getDoc(doc(db, "users", uid));
    if (userDoc.exists()) {
      return userDoc.data();
    }
    // Fallback: check if a username doc claims this uid
    const q = query(collection(db, "usernames"), where("uid", "==", uid));
    const snap = await getDocs(q);
    if (!snap.empty) {
      const claimedName = snap.docs[0].id;
      const profile = { uid, username: claimedName, createdAt: Date.now() };
      try {
        await setDoc(doc(db, "users", uid), profile);
      } catch {
        // write fallback
      }
      return profile;
    }
  } catch (err) {
    console.warn("Notice reading user profile:", err.message || err);
  }
  return null;
}

export async function claimUsername(uid, username, email) {
  const cleanUsername = username.trim().toLowerCase();
  if (!/^[a-z0-9_]{3,24}$/.test(cleanUsername)) {
    throw new Error("Username must be 3-24 letters, numbers, or underscores.");
  }
  const usernameRef = doc(db, "usernames", cleanUsername);
  const existingClaim = await getDoc(usernameRef);
  if (existingClaim.exists() && existingClaim.data().uid !== uid) {
    throw new Error("That username is already taken. Please choose another.");
  }

  // Claim username
  await setDoc(usernameRef, { uid, createdAt: Date.now() });
  
  // Set user doc
  const userProfile = {
    uid,
    username: cleanUsername,
    email: email || "",
    createdAt: Date.now()
  };
  await setDoc(doc(db, "users", uid), userProfile);
  return userProfile;
}

/**
 * Record that a user has opened a chat at the current timestamp
 */
export async function recordChatOpened(chatId, uid, username) {
  if (!chatId || !uid) return;
  try {
    const readRef = doc(db, "chats", chatId, "reads", uid);
    await setDoc(readRef, {
      uid,
      username: username || "",
      chatId,
      lastOpenedAt: Date.now()
    }, { merge: true });
  } catch (err) {
    console.warn("Could not record chat opened:", err);
  }
}

/**
 * Listen to real-time read receipts for all participants in a chat
 */
export function subscribeToChatReads(chatId, onUpdate) {
  if (!chatId) return () => {};
  try {
    const readsCol = collection(db, "chats", chatId, "reads");
    return onSnapshot(readsCol, (snapshot) => {
      const readMap = {};
      snapshot.forEach((docSnap) => {
        const data = docSnap.data();
        if (data.username) {
          readMap[data.username] = data.lastOpenedAt || 0;
        }
      });
      onUpdate(readMap);
    }, (error) => {
      console.warn("Error listening to chat reads:", error);
    });
  } catch (err) {
    console.warn("Could not subscribe to chat reads:", err);
    return () => {};
  }
}

/**
 * Record real-time typing status for a participant
 */
export async function recordUserTyping(chatId, uid, username, isTyping) {
  if (!chatId || !uid) return;
  try {
    const typingRef = doc(db, "chats", chatId, "typing", uid);
    await setDoc(typingRef, {
      uid,
      username: username || "",
      chatId,
      typing: Boolean(isTyping),
      updatedAt: Date.now()
    }, { merge: true });
  } catch (err) {
    console.warn("Could not record typing status:", err);
  }
}

/**
 * Listen to real-time typing status for all participants in a chat
 */
export function subscribeToChatTyping(chatId, onUpdate) {
  if (!chatId) return () => {};
  try {
    const typingCol = collection(db, "chats", chatId, "typing");
    return onSnapshot(typingCol, (snapshot) => {
      const typingMap = {};
      const now = Date.now();
      snapshot.forEach((docSnap) => {
        const data = docSnap.data();
        if (data.username && data.typing && (now - (data.updatedAt || 0) < 5000)) {
          typingMap[data.username] = true;
        }
      });
      onUpdate(typingMap);
    }, (error) => {
      console.warn("Error listening to chat typing:", error);
    });
  } catch (err) {
    console.warn("Could not subscribe to chat typing:", err);
    return () => {};
  }
}

/**
 * Fetch all registered DuoChat users for discovery and direct messaging
 */
export async function getAllRegisteredUsers(excludeUsername) {
  try {
    const snap = await getDocs(collection(db, "usernames"));
    const users = [];
    snap.forEach((docSnap) => {
      const u = docSnap.id;
      if (u && u !== excludeUsername) {
        users.push({ username: u, uid: docSnap.data().uid });
      }
    });
    return users;
  } catch (err) {
    console.warn("Could not fetch users list:", err);
    return [];
  }
}

/**
 * Save persistent chat key backup in Firestore for a user
 */
export async function savePersistentChatKey(chatId, uid, key) {
  if (!chatId || !uid || !key) return;
  try {
    await setDoc(doc(db, "chats", chatId, "keys", uid), {
      uid,
      chatId,
      key,
      createdAt: Date.now()
    }, { merge: true });
  } catch (err) {
    console.warn("Could not save persistent chat key:", err);
  }
}

/**
 * Retrieve persistent chat key backup from Firestore for a user
 */
export async function getPersistentChatKey(chatId, uid) {
  if (!chatId || !uid) return null;
  try {
    const snap = await getDoc(doc(db, "chats", chatId, "keys", uid));
    if (snap.exists()) {
      return snap.data().key;
    }
  } catch (err) {
    console.warn("Could not retrieve persistent chat key:", err);
  }
  return null;
}

/**
 * Send an Instagram-style direct message request to another user
 */
export async function sendDirectChatRequest({ senderUid, senderUsername, recipientUid, recipientUsername, chatId, chatKey }) {
  const requestId = `${senderUid}_${recipientUid}_${chatId}`;
  const requestData = {
    id: requestId,
    senderUid,
    senderUsername,
    recipientUid,
    recipientUsername,
    chatId,
    chatKey,
    status: "pending",
    createdAt: Date.now()
  };
  await setDoc(doc(db, "chatRequests", requestId), requestData);
  // Also save key backup for sender
  await savePersistentChatKey(chatId, senderUid, chatKey);
  return requestData;
}

/**
 * Subscribe in real time to incoming direct message requests for a user
 */
export function subscribeToIncomingRequests(recipientUid, onUpdate) {
  if (!recipientUid) return () => {};
  try {
    const q = query(
      collection(db, "chatRequests"),
      where("recipientUid", "==", recipientUid),
      where("status", "==", "pending")
    );
    return onSnapshot(q, (snapshot) => {
      const requests = [];
      snapshot.forEach((docSnap) => {
        requests.push({ ...docSnap.data(), id: docSnap.id });
      });
      onUpdate(requests);
    }, (err) => {
      console.warn("Error listening to incoming requests:", err);
    });
  } catch (err) {
    console.warn("Could not subscribe to incoming requests:", err);
    return () => {};
  }
}

/**
 * Accept an incoming message request
 */
export async function acceptDirectChatRequest(request, currentUserUid) {
  const reqRef = doc(db, "chatRequests", request.id);
  await setDoc(reqRef, { status: "accepted" }, { merge: true });
  // Save encryption key for recipient
  await savePersistentChatKey(request.chatId, currentUserUid, request.chatKey);
}

/**
 * Decline / dismiss a message request
 */
export async function declineDirectChatRequest(requestId) {
  const reqRef = doc(db, "chatRequests", requestId);
  await deleteDoc(reqRef);
}

/**
 * Save chat record to Firestore
 */
export async function saveFirestoreChat(chat) {
  if (!chat || !chat.id) return;
  try {
    await setDoc(doc(db, "chats", chat.id), {
      id: chat.id,
      members: chat.members || [],
      createdAt: chat.createdAt || Date.now(),
      updatedAt: Date.now()
    }, { merge: true });
  } catch (err) {
    console.warn("Could not save chat to firestore:", err);
  }
}

/**
 * Subscribe to all chats for the current user in real time
 */
export function subscribeToUserChats(username, onUpdate) {
  if (!username) return () => {};
  try {
    const q = query(
      collection(db, "chats"),
      where("members", "array-contains", username)
    );
    return onSnapshot(q, (snapshot) => {
      const chatList = [];
      snapshot.forEach((docSnap) => {
        chatList.push({ ...docSnap.data(), id: docSnap.id });
      });
      chatList.sort((a, b) => (b.updatedAt || b.createdAt || 0) - (a.updatedAt || a.createdAt || 0));
      onUpdate(chatList);
    }, (err) => {
      console.warn("Error listening to chats:", err);
    });
  } catch (err) {
    console.warn("Could not subscribe to chats:", err);
    return () => {};
  }
}

/**
 * Save chat message to Firestore subcollection
 */
export async function saveFirestoreMessage(chatId, message) {
  if (!chatId || !message) return;
  const messageId = message.id || `${message.ts}:${message.sender}`;
  try {
    await setDoc(doc(db, "chats", chatId, "messages", messageId), {
      id: messageId,
      chatId,
      sender: message.sender,
      text: message.text,
      ts: message.ts || Date.now()
    });
    await setDoc(doc(db, "chats", chatId), {
      lastMessageTs: message.ts || Date.now(),
      updatedAt: Date.now()
    }, { merge: true });
  } catch (err) {
    console.warn("Could not save message to firestore:", err);
  }
}

/**
 * Subscribe to messages in a chat conversation in real time
 */
export function subscribeToChatMessages(chatId, onMessage) {
  if (!chatId) return () => {};
  try {
    const q = query(collection(db, "chats", chatId, "messages"));
    return onSnapshot(q, (snapshot) => {
      snapshot.docChanges().forEach((change) => {
        if (change.type === "added") {
          onMessage(change.doc.data());
        }
      });
    }, (err) => {
      console.warn("Error listening to chat messages:", err);
    });
  } catch (err) {
    console.warn("Could not subscribe to chat messages:", err);
    return () => {};
  }
}

/**
 * Delete a chat in Firestore
 */
export async function deleteFirestoreChat(chatId) {
  if (!chatId) return;
  try {
    await deleteDoc(doc(db, "chats", chatId));
  } catch (err) {
    console.warn("Could not delete firestore chat:", err);
  }
}

export {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signInWithPopup,
  signInWithRedirect,
  getRedirectResult,
  fbSignOut,
  onAuthStateChanged,
  updateProfile
};
