export type RustEdition = '2015' | '2018' | '2021' | '2024' | 'N/A' | 'Python 3.x' | 'Node.js/ES2024' | 'Go 1.22+' | 'C17/C++20' | 'Java 21' | 'Solidity ^0.8' | 'PHP 8.x' | 'C# .NET' | 'Polyglot Standard';

export type SupportedLanguage =
  | 'Rust'
  | 'Python'
  | 'TypeScript'
  | 'JavaScript'
  | 'Go'
  | 'C'
  | 'C++'
  | 'Java'
  | 'C#'
  | 'PHP'
  | 'Ruby'
  | 'Solidity'
  | 'Shell'
  | 'Polyglot';

export type VulnerabilitySeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type VulnerabilityCategory =
  | 'MEMORY_SAFETY'
  | 'CONCURRENCY_RACE'
  | 'UNSAFE_UB'
  | 'CRYPTOGRAPHIC_FAILURES'
  | 'LEGACY_EDITION'
  | 'SUPPLY_CHAIN'
  | 'INTEGER_OVERFLOW'
  | 'DESERIALIZATION_RCE'
  | 'INJECTION_SQL_CMD'
  | 'PROTOTYPE_POLLUTION'
  | 'REENTRANCY_WEB3'
  | 'BROKEN_ACCESS_AUTH'
  | 'SSRF_PATH_TRAVERSAL';

export type AuditTargetScope = 'FULL_REPO' | 'PULL_REQUEST';

export interface PullRequestMetadata {
  number: number;
  title: string;
  author: string;
  authorAvatar?: string;
  state: 'open' | 'closed' | 'merged';
  headBranch: string;
  baseBranch: string;
  htmlUrl: string;
  additions: number;
  deletions: number;
  changedFilesCount: number;
  mergedAt?: string;
  createdAt: string;
  body?: string;
}

export interface RepositoryMetadata {
  owner: string;
  name: string;
  fullName: string;
  description: string;
  stars: number;
  forks: number;
  openIssues: number;
  defaultBranch: string;
  language: string;
  url: string;
  fileCount: number;
  totalTreeFiles: number;
  scope?: AuditTargetScope;
  pullRequest?: PullRequestMetadata;
}

export interface SourceFile {
  path: string;
  size: number;
  content: string;
  language?: SupportedLanguage | string;
}

export interface RustVulnerability {
  id: string;
  file: string;
  line: number;
  title: string;
  severity: VulnerabilitySeverity;
  cwe: string;
  rustsecId?: string; // or CVE ID
  cvssScore: number;
  category: VulnerabilityCategory;
  description: string;
  unsafeRiskDetail: string;
  waveShockwaveRadius: string; // Wavefront blast radius
  quantumRiskDetail?: string;
  originalSnippet: string;
  remediatedSnippet: string;
  suggestion?: string; // Sugestão pericial de remediação e boas práticas em Português
  miriVerificationStatus: 'DETECTED_UB' | 'VERIFIED_SAFE' | 'COMPLIANT';
  clippyLintRule?: string;
  language?: SupportedLanguage | string;
  fixedVersion?: string;
}

// Alias for universal polyglot use
export type VulnerabilityItem = RustVulnerability;

export interface ZeroDayWaveHazard {
  id: string;
  moduleName: string;
  spectralEntropy: number; // 0.0 - 1.0 (Code complexity entropy & anomaly index)
  harmonicFrequency: string; // e.g. "CFG Branch Volatility"
  constructiveInterferenceScore: number; // 0 - 100 (Compound risk score)
  shockwaveBlastRadius: 'LOCAL_MODULE' | 'CRATE_BOUNDARY' | 'SYSTEM_PROCESS' | 'KERNEL_PANIC';
  theoreticalZeroDaySurface: string;
  waveFunctionCollapseRisk: string; // Invariant violation risk
  solitonDampenerRemediation: string; // Deterministic memory-safe remediation
  affectedLanguage?: string;
}

export interface QuantumCryptoMetrics {
  quantumReadinessScore: number; // 0 to 100 (Cryptographic posture score)
  shorAlgorithmVulnerability: 'SAFE' | 'VULNERABLE' | 'DEPRECATED'; // Legacy cipher status (e.g., MD5/SHA1/DES)
  groverResistanceBits: number; // e.g. 128, 256 (Effective security bits)
  detectedLegacyPrimitives: string[]; // e.g. ["MD5", "SHA-1", "DES", "RC4", "ECB-Mode"]
  recommendedPqcReplacements: string[]; // e.g. ["AES-256-GCM", "ChaCha20-Poly1305", "Ed25519", "Argon2id"]
  constantTimeCompliance: boolean;
  entropySourceAudit: string;
}

export interface BpmnStep {
  id: string;
  name: string;
  role: 'SOA_INGESTION' | 'SUPPLY_CHAIN_CVE' | 'AST_ANALYSIS' | 'WAVE_ZERO_DAY' | 'QUANTUM_CRYPTO' | 'CODE_REVIEW' | 'EXECUTIVE_SYNTHESIS';
  status: 'PENDING' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  description: string;
  progressPercent: number;
  timestamp?: string;
  details?: string[];
}

export interface SecurityTestCase {
  id: string;
  name: string;
  category: 'MIRI_UB' | 'FUZZ_BOUNDS' | 'CONCURRENCY_RACE' | 'QUANTUM_CRACK' | 'WAVE_SHOCKWAVE' | 'MEM_LEAK' | 'DESERIALIZATION' | 'INJECTION' | 'REENTRANCY';
  description: string;
  severity: VulnerabilitySeverity;
  status: 'PASSED' | 'FAILED' | 'BLOCKED' | 'FIXED';
  inputPayload: string;
  executionLog: string;
  mitigationVerification: string;
  targetLanguage?: string;
}

export interface AstMetrics {
  totalLines: number;
  codeLines: number;
  commentLines: number;
  blankLines: number;
  cyclomaticComplexity: {
    average: number;
    max: number;
    highComplexityPoints: number;
    riskLevel: 'LOW' | 'MODERATE' | 'HIGH' | 'EXTREME';
    fileBreakdown: Array<{
      file: string;
      complexity: number;
      functionsCount: number;
      maxFunctionComplexity: number;
    }>;
  };
  memorySafety: {
    unsafeBlocksCount: number;
    rawPointerDerefs: number;
    unboundedSlicingOrAlloc: number;
    transmuteCount: number;
    memoryLeakRiskCount: number;
    memorySafetyIndex: number; // 0 to 100
    memorySafetyPosture: 'OPTIMAL_MEMORY_SAFETY' | 'ACCEPTABLE_BOUNDED_UNSAFE' | 'ELEVATED_MEMORY_RISK' | 'CRITICAL_UB_HAZARDS';
  };
}

export interface SecurityAuditReport {
  id: string;
  timestamp: string;
  targetRepo: RepositoryMetadata;
  filesAudited: SourceFile[];
  overallSecurityScore: number; // 0 - 100
  editionDetected: RustEdition;
  detectedLanguages: string[];
  primaryLanguage: string;
  totalUnsafeBlocks: number;
  totalLinesAudited: number;
  vulnerabilities: RustVulnerability[];
  waveHazards: ZeroDayWaveHazard[];
  quantumMetrics: QuantumCryptoMetrics;
  executiveSummary: string;
  astMetrics?: AstMetrics;
  architectureVerdict: {
    dddCompliance: string;
    soaResilience: string;
    waveTheoryZeroDayPosture: string;
    iso27001Status: 'COMPLIANT' | 'NEEDS_REMEDIATION' | 'FAILING';
    soc2Status: 'PASS' | 'WARNING' | 'FAIL';
    nistSp800Status: 'ALIGNED' | 'GAPS_IDENTIFIED';
    rustSecAdvisories: number;
  };
  remediationRoadmap: Array<{
    phase: string;
    priority: number;
    actions: string[];
    estimatedEffort: string;
  }>;
  securityTests: SecurityTestCase[];
  dependencyAnalysis?: {
    manifestsScanned: string[];
    totalDependenciesCount: number;
    vulnerableCount: number;
    outdatedCount: number;
    rustsecCount: number;
    vulnerabilities: Array<{
      manifestPath: string;
      ecosystem: string;
      packageName: string;
      versionConstraint: string;
      advisoryId: string;
      cve?: string;
      severity: VulnerabilitySeverity;
      cvssScore: number;
      title: string;
      description: string;
      fixedVersion: string;
      advisoryUrl: string;
      remediation: string;
    }>;
    outdated: Array<{
      manifestPath: string;
      ecosystem: string;
      packageName: string;
      currentVersion: string;
      latestVersion: string;
      isMajorBehind: boolean;
      status: 'OUTDATED' | 'UP_TO_DATE' | 'DEPRECATED' | 'EOL';
      remediationCommand: string;
    }>;
  };
}

export type TargetMode = 'MIGRATE_RUST' | 'MIGRATE_GO' | 'REFRACTOR_IN_PLACE' | 'IN_PLACE';

export type SourceLanguage = SupportedLanguage;

export * from './domainEvents.ts';
export * from './grc.ts';
export * from './pqc.ts';
export * from './supplyChain.ts';


export type WebhookEvent = 'push' | 'pull_request' | 'workflow_dispatch' | 'issue_comment' | 'fuzz_crash' | 'workflow_run';

export interface FuzzCrashAlert {
  id: string;
  timestamp: string;
  target: 'ast_parser' | 'fuzz_structured_parser' | 'refactor_engine' | string;
  issueType: 'MEMORY_CORRUPTION' | 'BUFFER_OVERFLOW' | 'PANIC_OUT_OF_BOUNDS' | 'USE_AFTER_FREE' | 'UNDEFINED_BEHAVIOR' | 'DEADLY_SIGNAL' | 'TIMEOUT_HANG' | string;
  severity: 'CRITICAL' | 'HIGH';
  status: 'ACTIVE_UNRESOLVED' | 'INVESTIGATING' | 'RESOLVED';
  repoUrl: string;
  branch: string;
  commitSha?: string;
  prNumber?: number;
  workflowName: string;
  runUrl?: string;
  crashInputPreview?: string;
  rawErrorLog: string;
  stackTrace?: string[];
  remediationAdvice: string;
  author?: string;
}

export interface WebhookConfig {
  id: string;
  repoUrl: string;
  webhookUrl: string;
  secret: string;
  events: WebhookEvent[];
  autoAuditOnPush: boolean;
  active: boolean;
  createdAt: string;
  lastTriggeredAt?: string;
  totalDeliveries: number;
}

export interface WebhookDeliveryLog {
  id: string;
  timestamp: string;
  event: WebhookEvent;
  repoUrl: string;
  branch: string;
  commitSha?: string;
  commitMessage?: string;
  author?: string;
  status: 200 | 202 | 400 | 500;
  auditTriggered: boolean;
  vulnSummary?: {
    critical: number;
    high: number;
    medium: number;
    score: number;
  };
  durationMs: number;
  reportId?: string;
  report?: SecurityAuditReport;
}
