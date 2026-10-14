import {
  collection,
  deleteDoc,
  doc,
  getDoc,
  getDocs,
  limit,
  orderBy,
  query,
  serverTimestamp,
  setDoc,
  writeBatch,
} from "firebase/firestore";
import { firestore } from "./firebase";

export type StoredScanSummary = {
  id: string;
  kind: "url" | "message";
  hostname?: string;
  riskLevel: string;
  riskScore: number;
  indicators: { code: string; title: string; detail: string }[];
  recommendations: string[];
  evaluatedAt: string;
};

function requireFirestore() {
  if (!firestore) throw new Error("Firebase is not configured.");
  return firestore;
}

export async function getCloudHistory(uid: string): Promise<StoredScanSummary[]> {
  const db = requireFirestore();
  const scans = collection(db, "users", uid, "scans");
  const snapshot = await getDocs(query(scans, orderBy("createdAt", "desc"), limit(100)));
  return snapshot.docs.map((record) => {
    const data = record.data();
    return {
      id: record.id,
      kind: data.kind === "url" ? "url" : "message",
      ...(typeof data.hostname === "string" ? { hostname: data.hostname } : {}),
      riskLevel: typeof data.riskLevel === "string" ? data.riskLevel : "low",
      riskScore: typeof data.riskScore === "number" ? data.riskScore : 0,
      indicators: Array.isArray(data.indicators) ? data.indicators : [],
      recommendations: Array.isArray(data.recommendations) ? data.recommendations : [],
      evaluatedAt: typeof data.evaluatedAt === "string" ? data.evaluatedAt : new Date().toISOString(),
    } satisfies StoredScanSummary;
  });
}

export async function saveCloudHistory(uid: string, record: StoredScanSummary) {
  const db = requireFirestore();
  const { id, ...metadata } = record;
  await setDoc(doc(db, "users", uid, "scans", id), {
    ...metadata,
    createdAt: serverTimestamp(),
  });
  const scans = await getDocs(query(collection(db, "users", uid, "scans"), orderBy("createdAt", "desc"), limit(101)));
  if (scans.size > 100) {
    const batch = writeBatch(db);
    scans.docs.slice(100).forEach((oldest) => batch.delete(oldest.ref));
    await batch.commit();
  }
}

export async function deleteCloudHistoryItem(uid: string, id: string) {
  await deleteDoc(doc(requireFirestore(), "users", uid, "scans", id));
}

export async function clearCloudHistory(uid: string) {
  const db = requireFirestore();
  const reference = collection(db, "users", uid, "scans");
  while (true) {
    const scans = await getDocs(query(reference, limit(450)));
    if (scans.empty) return;
    const batch = writeBatch(db);
    scans.docs.forEach((record) => batch.delete(record.ref));
    await batch.commit();
    if (scans.size < 450) return;
  }
}

export async function getCloudLanguage(uid: string): Promise<"en" | "hi" | "te" | null> {
  const snapshot = await getDoc(doc(requireFirestore(), "users", uid));
  const value = snapshot.data()?.preferredLanguage;
  return value === "en" || value === "hi" || value === "te" ? value : null;
}

export async function saveCloudLanguage(uid: string, language: "en" | "hi" | "te") {
  await setDoc(doc(requireFirestore(), "users", uid), { preferredLanguage: language }, { merge: true });
}

export async function getCloudLearningProgress(uid: string): Promise<string[]> {
  const snapshot = await getDocs(collection(requireFirestore(), "users", uid, "learning_progress"));
  return snapshot.docs.filter((record) => record.data().completed === true).map((record) => record.id);
}

export async function saveCloudLearningProgress(uid: string, moduleId: string, completed: boolean) {
  const db = requireFirestore();
  await setDoc(doc(db, "users", uid, "learning_progress", moduleId), {
    completed,
    updatedAt: serverTimestamp(),
  });
}
