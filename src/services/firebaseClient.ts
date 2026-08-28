import { initializeApp, getApps, getApp } from 'firebase/app';
import { 
  initializeFirestore,
  getFirestore, 
  collection, 
  doc, 
  setDoc, 
  getDoc, 
  getDocs, 
  query, 
  orderBy, 
  limit, 
  deleteDoc, 
  onSnapshot 
} from 'firebase/firestore';
import { getAuth, signInAnonymously, onAuthStateChanged, type User } from 'firebase/auth';
import firebaseConfig from '../../firebase-applet-config.json';

const app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApp();

const dbId = firebaseConfig.firestoreDatabaseId && firebaseConfig.firestoreDatabaseId !== '(default)'
  ? firebaseConfig.firestoreDatabaseId
  : undefined;

// Use initializeFirestore with auto-detect long polling for maximum compatibility in iframe/sandboxed environments
export const db = initializeFirestore(app, {
  experimentalAutoDetectLongPolling: true,
  ignoreUndefinedProperties: true,
}, dbId);

export const auth = getAuth(app);

// Authenticate anonymously or existing session
export const ensureAuth = async (): Promise<User | null> => {
  if (auth.currentUser) {
    return auth.currentUser;
  }
  try {
    const userCredential = await signInAnonymously(auth);
    return userCredential.user;
  } catch (error) {
    console.warn('Firebase anonymous auth fallback or disabled:', error);
    return null;
  }
};

export { collection, doc, setDoc, getDoc, getDocs, query, orderBy, limit, deleteDoc, onSnapshot };
