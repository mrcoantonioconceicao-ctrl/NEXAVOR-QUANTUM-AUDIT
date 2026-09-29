import { db, collection, doc, setDoc, getDocs, deleteDoc, handleFirestoreError, OperationType } from './firebaseClient.ts';

export interface LinkedRepository {
  id: string;
  repoUrl: string;
  repoFullName: string;
  targetBranch: string; // e.g. 'main' or 'master'
  autoReauditOnPush: boolean;
  secret: string;
  webhookUrl: string;
  linkedAt: string;
  lastAuditAt?: string;
  lastAuditScore?: number;
  totalReaudits: number;
  status: 'ACTIVE_LINKED' | 'PAUSED' | 'SYNCING';
  lastCommitSha?: string;
  lastCommitMessage?: string;
  lastCommitAuthor?: string;
}

export class LinkedReposService {
  /**
   * Fetches all linked repositories for user profile from Express server & Firestore
   */
  static async getLinkedRepos(): Promise<LinkedRepository[]> {
    try {
      const res = await fetch('/api/linked-repos');
      if (res.ok) {
        const data = await res.json();
        if (data.repos && Array.isArray(data.repos)) {
          return data.repos;
        }
      }
    } catch (err) {
      console.warn('Backend /api/linked-repos offline, checking Firestore fallback:', err);
    }

    // Firestore fallback
    try {
      const querySnap = await getDocs(collection(db, 'linked_repositories'));
      const list: LinkedRepository[] = [];
      querySnap.forEach((docSnap) => {
        list.push(docSnap.data() as LinkedRepository);
      });
      return list;
    } catch (err) {
      handleFirestoreError(err, OperationType.GET, 'linked_repositories');
      return [];
    }
  }

  /**
   * Links a GitHub repository directly to user profile with automatic re-audit on push to main branch
   */
  static async linkRepository(data: {
    repoUrl: string;
    targetBranch?: string;
    autoReauditOnPush?: boolean;
    secret?: string;
  }): Promise<LinkedRepository> {
    const res = await fetch('/api/linked-repos', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Falha ao vincular repositório ao perfil.');
    }

    const result = await res.json();
    const linkedRepo: LinkedRepository = result.repo;

    // Sync to Firestore for persistent profile storage
    try {
      await setDoc(doc(db, 'linked_repositories', linkedRepo.id), linkedRepo, { merge: true });
    } catch (fsErr) {
      console.warn('Firestore write warning:', fsErr);
    }

    return linkedRepo;
  }

  /**
   * Unlinks a repository from user profile
   */
  static async unlinkRepository(id: string): Promise<boolean> {
    const res = await fetch(`/api/linked-repos/${id}`, { method: 'DELETE' });
    if (!res.ok) {
      throw new Error('Falha ao desvincular repositório.');
    }

    try {
      await deleteDoc(doc(db, 'linked_repositories', id));
    } catch (err) {
      console.warn('Firestore delete warning:', err);
    }

    return true;
  }

  /**
   * Toggles auto re-audit on push or updates target branch
   */
  static async updateLinkedRepo(
    id: string,
    updates: Partial<LinkedRepository>
  ): Promise<LinkedRepository> {
    const res = await fetch(`/api/linked-repos/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(updates),
    });

    if (!res.ok) {
      throw new Error('Falha ao atualizar configurações do repositório vinculado.');
    }

    const data = await res.json();
    const updated: LinkedRepository = data.repo;

    try {
      await setDoc(doc(db, 'linked_repositories', id), updated, { merge: true });
    } catch (err) {
      console.warn('Firestore update warning:', err);
    }

    return updated;
  }

  /**
   * Simulates a `git push origin main` event to test the automatic re-audit pipeline in real time
   */
  static async simulatePushToMain(repoUrl: string, commitMessage?: string, author?: string): Promise<any> {
    const res = await fetch('/api/linked-repos/simulate-push', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repoUrl,
        branch: 'main',
        commitMessage: commitMessage || 'feat(sec): push trigger automatic re-audit pipeline on main branch',
        author: author || 'mrcoantonioconceicao-ctrl',
      }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Falha ao simular evento de push na branch main.');
    }

    return await res.json();
  }
}
