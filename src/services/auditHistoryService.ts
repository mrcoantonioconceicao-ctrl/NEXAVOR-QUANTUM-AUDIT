import { SecurityAuditReport, RustVulnerability, ZeroDayWaveHazard } from '../domain/types.ts';
import { 
  db, 
  ensureAuth, 
  collection, 
  doc, 
  setDoc, 
  getDocs, 
  deleteDoc, 
  query, 
  orderBy, 
  limit 
} from './firebaseClient.ts';

const STORAGE_KEY = 'qaudit_session_history_v1';
const FIRESTORE_COLLECTION = 'audit_sessions';

export interface AuditSessionSnapshot {
  id: string;
  sessionId: string;
  timestamp: string;
  repoFullName: string;
  repoName: string;
  repoOwner: string;
  score: number;
  primaryLanguage: string;
  commitOrBranch: string;
  filesCount: number;
  totalLines: number;
  vulnerabilitiesCount: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  waveHazardsCount: number;
  quantumScore: number;
  report: SecurityAuditReport;
}

export interface VulnerabilityDiffItem {
  vulnerability: RustVulnerability;
  status: 'NEW' | 'FIXED' | 'PERSISTING';
  introducedInSessionId?: string;
  historicalNote?: string;
}

export interface AuditDiffResult {
  currentSession: SecurityAuditReport;
  baselineSession: SecurityAuditReport;
  scoreDelta: number; // current - baseline
  totalVulnDelta: number;
  criticalDelta: number;
  highDelta: number;
  mediumDelta: number;
  newVulnerabilities: RustVulnerability[];
  fixedVulnerabilities: RustVulnerability[];
  persistingVulnerabilities: RustVulnerability[];
  allDiffItems: VulnerabilityDiffItem[];
  waveHazardDelta: {
    newHazards: ZeroDayWaveHazard[];
    fixedHazards: ZeroDayWaveHazard[];
    persistingHazards: ZeroDayWaveHazard[];
    deltaCount: number;
  };
  quantumReadinessDelta: number;
  verdict: 'CRITICAL_REGRESSION' | 'REGRESSION' | 'IMPROVED' | 'STABLE' | 'EQUAL';
  verdictMessage: string;
}

/**
 * Retrieves all saved audit sessions from localStorage cache immediately,
 * and fetches the latest from Firebase Firestore.
 */
export function getAuditHistory(repoFullName?: string): AuditSessionSnapshot[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const list: AuditSessionSnapshot[] = JSON.parse(raw);
    if (!Array.isArray(list)) return [];

    if (repoFullName) {
      const normalizedTarget = repoFullName.toLowerCase().trim();
      return list.filter(
        (item) => item.repoFullName.toLowerCase().trim() === normalizedTarget
      );
    }

    return list.sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );
  } catch (err) {
    console.warn('Failed to load audit history from localStorage:', err);
    return [];
  }
}

/**
 * Syncs and pulls history from Firebase Firestore into local state.
 */
export async function syncHistoryFromFirebase(): Promise<AuditSessionSnapshot[]> {
  try {
    await ensureAuth();
    const q = query(collection(db, FIRESTORE_COLLECTION), orderBy('timestamp', 'desc'), limit(25));
    const snapshot = await getDocs(q);
    const remoteList: AuditSessionSnapshot[] = [];
    
    snapshot.forEach((docSnap) => {
      const data = docSnap.data() as AuditSessionSnapshot;
      if (data && data.id) {
        remoteList.push(data);
      }
    });

    if (remoteList.length > 0) {
      // Merge remote list with local storage
      const localList = getAuditHistory();
      const combinedMap = new Map<string, AuditSessionSnapshot>();
      
      [...remoteList, ...localList].forEach((item) => {
        if (!combinedMap.has(item.id)) {
          combinedMap.set(item.id, item);
        }
      });
      
      const merged = Array.from(combinedMap.values()).sort(
        (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
      ).slice(0, 20);

      localStorage.setItem(STORAGE_KEY, JSON.stringify(merged));
      return merged;
    }
  } catch (err) {
    console.warn('Firebase sync notice (offline or read error):', err);
  }
  return getAuditHistory();
}

/**
 * Saves an audit report into session history (Local + Firebase Firestore).
 */
export function saveAuditSession(report: SecurityAuditReport): AuditSessionSnapshot {
  const history = getAuditHistory();

  const critical = (report.vulnerabilities || []).filter((v) => v.severity === 'CRITICAL').length;
  const high = (report.vulnerabilities || []).filter((v) => v.severity === 'HIGH').length;
  const medium = (report.vulnerabilities || []).filter((v) => v.severity === 'MEDIUM').length;
  const low = (report.vulnerabilities || []).filter((v) => v.severity === 'LOW' || v.severity === 'INFORMATIONAL').length;

  const snapshot: AuditSessionSnapshot = {
    id: report.id || `session-${Date.now()}`,
    sessionId: `SES-${new Date(report.timestamp || Date.now()).toISOString().replace(/[-:T.Z]/g, '').slice(0, 14)}`,
    timestamp: report.timestamp || new Date().toISOString(),
    repoFullName: report.targetRepo?.fullName || 'unknown-repo',
    repoName: report.targetRepo?.name || 'unknown',
    repoOwner: report.targetRepo?.owner || 'unknown',
    score: report.overallSecurityScore ?? 0,
    primaryLanguage: report.primaryLanguage || report.targetRepo?.language || 'Polyglot',
    commitOrBranch: report.targetRepo?.defaultBranch || 'main',
    filesCount: report.filesAudited?.length || 0,
    totalLines: report.totalLinesAudited || 0,
    vulnerabilitiesCount: {
      total: (report.vulnerabilities || []).length,
      critical,
      high,
      medium,
      low,
    },
    waveHazardsCount: (report.waveHazards || []).length,
    quantumScore: report.quantumMetrics?.quantumReadinessScore || 0,
    report,
  };

  // Check if this exact session ID or identical report already exists
  const existingIdx = history.findIndex(
    (h) => h.id === snapshot.id || (h.timestamp === snapshot.timestamp && h.repoFullName === snapshot.repoFullName)
  );

  let updatedList: AuditSessionSnapshot[];
  if (existingIdx >= 0) {
    updatedList = [...history];
    updatedList[existingIdx] = snapshot;
  } else {
    // Keep max 20 historical sessions
    updatedList = [snapshot, ...history].slice(0, 20);
  }

  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updatedList));
  } catch (err) {
    console.warn('Failed to save audit session into localStorage:', err);
  }

  // Asynchronous Firebase Cloud Persistence
  (async () => {
    try {
      await ensureAuth();
      const docRef = doc(db, FIRESTORE_COLLECTION, snapshot.id);
      // Clean undefined fields for Firestore
      const cleanPayload = JSON.parse(JSON.stringify(snapshot));
      await setDoc(docRef, cleanPayload, { merge: true });
    } catch (firebaseErr) {
      console.warn('Firebase Firestore async persist warning:', firebaseErr);
    }
  })();

  return snapshot;
}

/**
 * Removes a session snapshot from history (Local + Firebase).
 */
export function deleteAuditSession(id: string): void {
  const history = getAuditHistory();
  const updated = history.filter((h) => h.id !== id && h.sessionId !== id);
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch (err) {
    console.warn('Failed to delete session:', err);
  }

  // Delete from Firebase
  (async () => {
    try {
      await ensureAuth();
      const docRef = doc(db, FIRESTORE_COLLECTION, id);
      await deleteDoc(docRef);
    } catch (err) {
      console.warn('Failed to delete session from Firebase:', err);
    }
  })();
}

/**
 * Clears all audit history.
 */
export function clearAuditHistory(): void {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch (err) {
    console.warn('Failed to clear history:', err);
  }
}

/**
 * Computes deep fingerprint key for matching vulnerabilities across scans.
 */
function getVulnFingerprint(vuln: RustVulnerability): string {
  const cleanFile = (vuln.file || '').replace(/\\/g, '/').toLowerCase();
  const titleNorm = (vuln.title || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  const cweNorm = (vuln.cwe || '').toLowerCase().trim();
  return `${cleanFile}::${cweNorm}::${titleNorm}`;
}

/**
 * Computes deep fingerprint for wave hazards.
 */
function getHazardFingerprint(hazard: ZeroDayWaveHazard): string {
  const mod = (hazard.moduleName || '').toLowerCase().trim();
  const surface = (hazard.theoreticalZeroDaySurface || '').toLowerCase().slice(0, 40).replace(/[^a-z0-9]/g, '');
  return `${mod}::${surface}`;
}

/**
 * Compares current scan results against a baseline inspection session.
 */
export function compareAuditReports(
  current: SecurityAuditReport,
  baseline: SecurityAuditReport
): AuditDiffResult {
  const baselineMap = new Map<string, RustVulnerability>();
  const currentMap = new Map<string, RustVulnerability>();

  (baseline.vulnerabilities || []).forEach((v) => {
    baselineMap.set(getVulnFingerprint(v), v);
  });

  (current.vulnerabilities || []).forEach((v) => {
    currentMap.set(getVulnFingerprint(v), v);
  });

  const newVulnerabilities: RustVulnerability[] = [];
  const fixedVulnerabilities: RustVulnerability[] = [];
  const persistingVulnerabilities: RustVulnerability[] = [];
  const allDiffItems: VulnerabilityDiffItem[] = [];

  // Identify new & persisting vulnerabilities
  currentMap.forEach((vuln, fp) => {
    if (baselineMap.has(fp)) {
      persistingVulnerabilities.push(vuln);
      allDiffItems.push({
        vulnerability: vuln,
        status: 'PERSISTING',
        historicalNote: 'Identificado no scan anterior e ainda persiste no código atual.',
      });
    } else {
      newVulnerabilities.push(vuln);
      allDiffItems.push({
        vulnerability: vuln,
        status: 'NEW',
        introducedInSessionId: current.id,
        historicalNote: 'Nova vulnerabilidade introduzida na versão recente.',
      });
    }
  });

  // Identify fixed vulnerabilities
  baselineMap.forEach((vuln, fp) => {
    if (!currentMap.has(fp)) {
      fixedVulnerabilities.push(vuln);
      allDiffItems.push({
        vulnerability: vuln,
        status: 'FIXED',
        historicalNote: 'Vulnerabilidade sanada ou remediada com sucesso em relação ao baseline.',
      });
    }
  });

  // Compare Wave Hazards
  const baselineHazardMap = new Map<string, ZeroDayWaveHazard>();
  const currentHazardMap = new Map<string, ZeroDayWaveHazard>();

  (baseline.waveHazards || []).forEach((h) => {
    baselineHazardMap.set(getHazardFingerprint(h), h);
  });
  (current.waveHazards || []).forEach((h) => {
    currentHazardMap.set(getHazardFingerprint(h), h);
  });

  const newHazards: ZeroDayWaveHazard[] = [];
  const fixedHazards: ZeroDayWaveHazard[] = [];
  const persistingHazards: ZeroDayWaveHazard[] = [];

  currentHazardMap.forEach((hazard, fp) => {
    if (baselineHazardMap.has(fp)) {
      persistingHazards.push(hazard);
    } else {
      newHazards.push(hazard);
    }
  });

  baselineHazardMap.forEach((hazard, fp) => {
    if (!currentHazardMap.has(fp)) {
      fixedHazards.push(hazard);
    }
  });

  const scoreDelta = (current.overallSecurityScore ?? 0) - (baseline.overallSecurityScore ?? 0);
  const totalVulnDelta = (current.vulnerabilities || []).length - (baseline.vulnerabilities || []).length;
  
  const curCritical = (current.vulnerabilities || []).filter((v) => v.severity === 'CRITICAL').length;
  const baseCritical = (baseline.vulnerabilities || []).filter((v) => v.severity === 'CRITICAL').length;
  const criticalDelta = curCritical - baseCritical;

  const curHigh = (current.vulnerabilities || []).filter((v) => v.severity === 'HIGH').length;
  const baseHigh = (baseline.vulnerabilities || []).filter((v) => v.severity === 'HIGH').length;
  const highDelta = curHigh - baseHigh;

  const curMedium = (current.vulnerabilities || []).filter((v) => v.severity === 'MEDIUM').length;
  const baseMedium = (baseline.vulnerabilities || []).filter((v) => v.severity === 'MEDIUM').length;
  const mediumDelta = curMedium - baseMedium;

  const quantumReadinessDelta =
    (current.quantumMetrics?.quantumReadinessScore ?? 0) -
    (baseline.quantumMetrics?.quantumReadinessScore ?? 0);

  // Verdict calculation
  let verdict: AuditDiffResult['verdict'] = 'EQUAL';
  let verdictMessage = 'O estado de segurança permaneceu inalterado.';

  if (criticalDelta > 0 || (highDelta > 1 && scoreDelta < -10)) {
    verdict = 'CRITICAL_REGRESSION';
    verdictMessage = `REGRESSÃO CRÍTICA: +${criticalDelta} falhas críticas introduzidas. Queda de ${Math.abs(scoreDelta)} pts no Score de Segurança.`;
  } else if (scoreDelta < -2 || totalVulnDelta > 0) {
    verdict = 'REGRESSION';
    verdictMessage = `REGRESSÃO DE SEGURANÇA: ${newVulnerabilities.length} novas vulnerabilidades detectadas. Redução de ${Math.abs(scoreDelta)} pts.`;
  } else if (scoreDelta > 3 || fixedVulnerabilities.length > 0) {
    verdict = 'IMPROVED';
    verdictMessage = `EVOLUÇÃO POSITIVA: ${fixedVulnerabilities.length} vulnerabilidades eliminadas! Aumento de +${scoreDelta} pts no Score de Segurança.`;
  } else if (Math.abs(scoreDelta) <= 2 && totalVulnDelta === 0) {
    verdict = 'STABLE';
    verdictMessage = 'ESTABILIDADE: Métricas e posture de segurança consistentes com a baseline.';
  }

  return {
    currentSession: current,
    baselineSession: baseline,
    scoreDelta,
    totalVulnDelta,
    criticalDelta,
    highDelta,
    mediumDelta,
    newVulnerabilities,
    fixedVulnerabilities,
    persistingVulnerabilities,
    allDiffItems,
    waveHazardDelta: {
      newHazards,
      fixedHazards,
      persistingHazards,
      deltaCount: (current.waveHazards || []).length - (baseline.waveHazards || []).length,
    },
    quantumReadinessDelta,
    verdict,
    verdictMessage,
  };
}

/**
 * Creates a synthetic baseline session representation for comparison.
 */
export function generateSyntheticBaselineSession(report: SecurityAuditReport): SecurityAuditReport {
  return {
    ...report,
    id: `synthetic-baseline-${Date.now()}`,
    timestamp: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
    overallSecurityScore: Math.max(10, (report.overallSecurityScore || 70) - 15),
    vulnerabilities: report.vulnerabilities.slice(0, Math.max(1, report.vulnerabilities.length - 1)),
  };
}
