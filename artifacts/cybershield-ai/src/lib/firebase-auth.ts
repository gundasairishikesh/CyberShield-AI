import { onAuthStateChanged, signInWithEmailAndPassword, createUserWithEmailAndPassword, signOut, type User } from "firebase/auth";
import { useEffect, useState } from "react";
import { firebaseAuth, firebaseConfigured } from "./firebase";

export function useFirebaseAuth() {
  const [user, setUser] = useState<User | null>(null);
  const [ready, setReady] = useState(!firebaseConfigured);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!firebaseAuth) {
      setReady(true);
      return;
    }
    return onAuthStateChanged(firebaseAuth, (nextUser) => {
      setUser(nextUser);
      setReady(true);
    }, () => {
      setUser(null);
      setReady(true);
      setError("Could not confirm your account session. Check Firebase configuration.");
    });
  }, []);

  async function signIn(email: string, password: string) {
    if (!firebaseAuth) throw new Error("Firebase authentication is not configured yet.");
    setError("");
    try {
      await signInWithEmailAndPassword(firebaseAuth, email, password);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Sign-in could not be completed.";
      setError(message);
      throw cause;
    }
  }

  async function register(email: string, password: string) {
    if (!firebaseAuth) throw new Error("Firebase authentication is not configured yet.");
    setError("");
    try {
      await createUserWithEmailAndPassword(firebaseAuth, email, password);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Account creation could not be completed.";
      setError(message);
      throw cause;
    }
  }

  async function logOut() {
    if (!firebaseAuth) return;
    setError("");
    try {
      await signOut(firebaseAuth);
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Sign-out could not be completed.";
      setError(message);
      throw cause;
    }
  }

  return { user, ready, error, setError, signIn, register, logOut };
}
