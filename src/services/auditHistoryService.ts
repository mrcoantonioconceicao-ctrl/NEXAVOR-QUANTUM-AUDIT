import { SecurityAuditReport, RustVulnerability, ZeroDayWaveHazard } from '../domain/types.ts';

const STORAGE_KEY = 'qaudit_session_history_v1';

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
 * Retrieves all saved audit sessions from localStorage.
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
 * Saves an audit report into session history.
 */
export function saveAuditSession(report: SecurityAuditReport): AuditSessionSnapshot {
  const history = getAuditHistory();

  const critical = report.vulnerabilities.filter((v) => v.severity === 'CRITICAL').length;
  const high = report.vulnerabilities.filter((v) => v.severity === 'HIGH').length;
  const medium = report.vulnerabilities.filter((v) => v.severity === 'MEDIUM').length;
  const low = report.vulnerabilities.filter((v) => v.severity === 'LOW' || v.severity === 'INFORMATIONAL').length;

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
      total: report.vulnerabilities?.length || 0,
      critical,
      high,
      medium,
      low,
    },
    waveHazardsCount: report.waveHazards?.length || 0,
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

  return snapshot;
}

/**
 * Removes a session snapshot from history.
 */
export function deleteAuditSession(id: string): void {
  const history = getAuditHistory();
  const updated = history.filter((h) => h.id !== id && h.sessionId !== id);
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
  } catch (err) {
    console.warn('Failed to delete session:', err);
  }
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
  // Normalize file path and match key attributes
  const cleanFile = vuln.file.replace(/\\/g, '/').toLowerCase();
  const titleNorm = vuln.title.toLowerCase().replace(/[^a-z0-9]/g, '');
  const cweNorm = (vuln.cwe || '').toLowerCase().trim();
  return `${cleanFile}::${cweNorm}::${titleNorm}`;
}

/**
 * Computes deep fingerprint for wave hazards.
 */
function getHazardFingerprint(hazard: ZeroDayWaveHazard): string {
  const mod = hazard.moduleName.toLowerCase().trim();
  const surface = hazard.theoreticalZeroDaySurface.toLowerCase().slice(0, 40).replace(/[^a-z0-9]/g, '');
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

  baseline.vulnerabilities.forEach((v) => {
    baselineMap.set(getVulnFingerprint(v), v);
  });

  current.vulnerabilities.forEach((v) => {
    currentMap.set(getVulnFingerprint(v), v);
  });

  const newVulnerabilities: RustVulnerability[] = [];
  const persistingVulnerabilities: RustVulnerability[] = [];
  const fixedVulnerabilities: RustVulnerability[] = [];
  const allDiffItems: VulnerabilityDiffItem[] = [];

  // Check each vulnerability in current scan
  current.vulnerabilities.forEach((v) => {
    const fp = getVulnFingerprint(v);
    if (baselineMap.has(fp)) {
      persistingVulnerabilities.push(v);
      allDiffItems.push({
        vulnerability: v,
        status: 'PERSISTING',
        historicalNote: 'Detectada tanto na auditoria anterior quanto na atual.',
      });
    } else {
      newVulnerabilities.push(v);
      allDiffItems.push({
        vulnerability: v,
        status: 'NEW',
        introducedInSessionId: current.id,
        historicalNote: '⚠️ REGRESSÃO: Esta vulnerabilidade NÃO existia na sessão anterior e foi introduzida recentemente.',
      });
    }
  });

  // Check which baseline vulnerabilities are now gone (fixed)
  baseline.vulnerabilities.forEach((bVuln) => {
    const fp = getVulnFingerprint(bVuln);
    if (!currentMap.has(fp)) {
      fixedVulnerabilities.push(bVuln);
      allDiffItems.push({
        vulnerability: bVuln,
        status: 'FIXED',
        historicalNote: '✅ REMEDIADA: Vulnerabilidade resolvida e eliminada com sucesso no código atual.',
      });
    }
  });

  // Wave hazards diff
  const baselineHazards = new Map<string, ZeroDayWaveHazard>();
  baseline.waveHazards.forEach((h) => baselineHazards.set(getHazardFingerprint(h), h));
  const currentHazards = new Map<string, ZeroDayWaveHazard>();
  current.waveHazards.forEach((h) => currentHazards.set(getHazardFingerprint(h), h));

  const newHazards: ZeroDayWaveHazard[] = [];
  const fixedHazards: ZeroDayWaveHazard[] = [];
  const persistingHazards: ZeroDayWaveHazard[] = [];

  current.waveHazards.forEach((h) => {
    if (baselineHazards.has(getHazardFingerprint(h))) {
      persistingHazards.push(h);
    } else {
      newHazards.push(h);
    }
  });

  baseline.waveHazards.forEach((h) => {
    if (!currentHazards.has(getHazardFingerprint(h))) {
      fixedHazards.push(h);
    }
  });

  // Score deltas
  const currentScore = current.overallSecurityScore ?? 0;
  const baselineScore = baseline.overallSecurityScore ?? 0;
  const scoreDelta = currentScore - baselineScore;

  const currentCritical = current.vulnerabilities.filter((v) => v.severity === 'CRITICAL').length;
  const baselineCritical = baseline.vulnerabilities.filter((v) => v.severity === 'CRITICAL').length;
  const criticalDelta = currentCritical - baselineCritical;

  const currentHigh = current.vulnerabilities.filter((v) => v.severity === 'HIGH').length;
  const baselineHigh = baseline.vulnerabilities.filter((v) => v.severity === 'HIGH').length;
  const highDelta = currentHigh - baselineHigh;

  const currentMed = current.vulnerabilities.filter((v) => v.severity === 'MEDIUM').length;
  const baselineMed = baseline.vulnerabilities.filter((v) => v.severity === 'MEDIUM').length;
  const mediumDelta = currentMed - baselineMed;

  const totalVulnDelta = current.vulnerabilities.length - baseline.vulnerabilities.length;
  const quantumReadinessDelta =
    (current.quantumMetrics?.quantumReadinessScore ?? 0) -
    (baseline.quantumMetrics?.quantumReadinessScore ?? 0);

  // Verdict logic
  let verdict: 'CRITICAL_REGRESSION' | 'REGRESSION' | 'IMPROVED' | 'STABLE' | 'EQUAL' = 'EQUAL';
  let verdictMessage = 'Nenhuma alteração na postura de segurança entre as sessões.';

  const newCriticalOrHigh = newVulnerabilities.filter(
    (v) => v.severity === 'CRITICAL' || v.severity === 'HIGH'
  ).length;

  if (newCriticalOrHigh > 0 || criticalDelta > 0) {
    verdict = 'CRITICAL_REGRESSION';
    verdictMessage = `ALERTA DE REGRESSÃO CRÍTICA: ${newVulnerabilities.length} nova(s) vulnerabilidade(s) introduzida(s) desde o scan anterior, incluindo falhas de alta severidade.`;
  } else if (newVulnerabilities.length > 0 || scoreDelta < -3) {
    verdict = 'REGRESSION';
    verdictMessage = `REGRESSÃO DETECTADA: ${newVulnerabilities.length} nova(s) vulnerabilidade(s) detectada(s). Score de segurança reduziu em ${Math.abs(scoreDelta)} pontos.`;
  } else if (fixedVulnerabilities.length > 0 || scoreDelta > 0) {
    verdict = 'IMPROVED';
    verdictMessage = `EVOLUÇÃO POSITIVA: ${fixedVulnerabilities.length} vulnerabilidade(s) foram remediadas e o Score subiu +${scoreDelta} pontos!`;
  } else {
    verdict = 'STABLE';
    verdictMessage = 'Postura de segurança idêntica à baseline anterior.';
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
      deltaCount: current.waveHazards.length - baseline.waveHazards.length,
    },
    quantumReadinessDelta,
    verdict,
    verdictMessage,
  };
}

/**
 * Creates a realistic synthetic prior release/baseline for demo and instant comparison testing.
 */
export function generateSyntheticBaselineSession(current: SecurityAuditReport): SecurityAuditReport {
  const currentVulns = current.vulnerabilities || [];
  
  // Baseline had a subset of current vulns (so current introduced new ones), plus an old fixed vuln
  const subsetToKeep = currentVulns.slice(1); // excluding first item makes first item "NEW" in current!

  const oldFixedVuln: RustVulnerability = {
    id: 'HIST-LEGACY-009',
    file: current.filesAudited[0]?.path || 'src/legacy_crypto.rs',
    line: 45,
    title: 'Descontinuação de Primitiva Criptográfica MD5 / SHA-1 Desatualizada',
    severity: 'MEDIUM',
    cwe: 'CWE-327',
    cvssScore: 5.9,
    category: 'QUANTUM_CRYPTO',
    description: 'Hashing de senha e integridade utilizando algoritmo fraco e vulnerável a colisões.',
    unsafeRiskDetail: 'Vulnerabilidade a ataques de pré-imagem e colisão rápida.',
    waveShockwaveRadius: 'LOCAL_MODULE',
    originalSnippet: 'let hash = md5::compute(raw_input_token);',
    remediatedSnippet: 'let hash = sha2::Sha256::digest(raw_input_token);',
    miriVerificationStatus: 'COMPLIANT',
    language: current.primaryLanguage || 'Rust',
  };

  const baselineTimestamp = new Date(
    new Date(current.timestamp || Date.now()).getTime() - 24 * 3600 * 1000 * 3
  ).toISOString();

  return {
    ...current,
    id: `baseline-sim-${Date.now()}`,
    timestamp: baselineTimestamp,
    overallSecurityScore: Math.min(100, (current.overallSecurityScore || 70) + 12),
    vulnerabilities: [...subsetToKeep, oldFixedVuln],
    executiveSummary: `Auditoria de baseline histórica anterior (Release v1.2.0-baseline) para o repositório ${current.targetRepo.fullName}.`,
    targetRepo: {
      ...current.targetRepo,
      defaultBranch: 'release-v1.2.0',
    },
  };
}
