/**
 * Bounded Context: knowledgeGraph
 * Schema e Ontologia do Grafo de Conhecimento de Segurança para Neo4j / Memgraph / FalkorDB
 * Define as interfaces TypeScript fortemente tipadas para os nós (:CodeFile, :ASTFunction, :Vulnerability, :ComplianceRule, etc.)
 * e suas arestas de relacionamento no contexto de auditorias DevSecOps e Post-Quantum Cryptography (PQC).
 */

// ============================================================================
// 1. ENUMS E TIPOS BASE DA ONTOLOGIA
// ============================================================================

export type NodeLabel =
  | 'CodeFile'
  | 'ASTFunction'
  | 'CryptoAlgorithm'
  | 'Vulnerability'
  | 'ComplianceRule'
  | 'SBOMPackage';

export type RelationshipType =
  | 'CALLS'
  | 'USES_CRYPTO'
  | 'VIOLATES'
  | 'DEPENDS_ON'
  | 'HAS_VULNERABILITY'
  | 'AFFECTS_MODULE'
  | 'COMPLIES_WITH';

export type RiskSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'SAFE';

// ============================================================================
// 2. INTERFACES ESPECÍFICAS DE CADA NÓ (ENTIDADES NEO4J)
// ============================================================================

/**
 * Nó representando um Arquivo de Código Fonte ou Smart Contract (:CodeFile)
 */
export interface CodeFileNodeProperties {
  filePath: string;
  language: 'Rust' | 'TypeScript' | 'Solidity' | 'Go' | 'Python' | 'Config';
  isSmartContract: boolean;
  totalLines?: number;
  hashMd5?: string;
  securityScore?: number;
  lastAuditedAt?: string;
}

export interface CodeFileNode {
  id: string; // Ex: 'file_lib_rs'
  label: 'CodeFile';
  name: string; // Ex: 'programs/solana_sandbox_counter/src/lib.rs'
  riskLevel: RiskSeverity;
  properties: CodeFileNodeProperties;
}

/**
 * Nó representando uma Função ou Método extraído da Árvore Sintática Abstrata (:ASTFunction)
 */
export interface ASTFunctionNodeProperties {
  functionName: string;
  filePath: string;
  scope: 'public' | 'private' | 'restricted';
  mutableState: boolean;
  cpiCalls?: string[]; // Cross-Program Invocations
  mathOperations?: string[]; // Ex: 'counter.count += 1'
  hasCheckedMath?: boolean;
  cyclomaticComplexity?: number;
}

export interface ASTFunctionNode {
  id: string; // Ex: 'fn_increment'
  label: 'ASTFunction';
  name: string; // Ex: 'increment()'
  riskLevel: RiskSeverity;
  properties: ASTFunctionNodeProperties;
}

/**
 * Nó representando um Algoritmo Criptográfico identificado no código (:CryptoAlgorithm)
 */
export interface CryptoAlgorithmNodeProperties {
  algorithmName: string;
  cryptoType: 'Symmetric' | 'Asymmetric' | 'Hash' | 'Signatures' | 'KEM';
  quantumResistant: boolean;
  recommendedKeySize?: string;
  deprecatedSince?: string;
  standardReference?: string; // Ex: 'NIST FIPS 204 (ML-DSA)'
}

export interface CryptoAlgorithmNode {
  id: string; // Ex: 'crypto_rsa_2048'
  label: 'CryptoAlgorithm';
  name: string; // Ex: 'RSA-2048'
  riskLevel: RiskSeverity;
  properties: CryptoAlgorithmNodeProperties;
}

/**
 * Nó representando uma Vulnerabilidade de Segurança Detectada (:Vulnerability)
 */
export interface VulnerabilityNodeProperties {
  vulnId: string; // Ex: 'VULN-SOL-001', 'CVE-2024-1234'
  title: string;
  severity: RiskSeverity;
  cvssScore?: number;
  cwe?: string; // Ex: 'CWE-190: Integer Overflow'
  filePath?: string;
  description: string;
  remediationCode?: string;
}

export interface VulnerabilityNode {
  id: string; // Ex: 'vuln_sol_001'
  label: 'Vulnerability';
  name: string; // Ex: 'VULN-SOL-001: Integer Overflow'
  riskLevel: RiskSeverity;
  properties: VulnerabilityNodeProperties;
}

/**
 * Nó representando uma Regra de Conformidade e Norma de Governança (:ComplianceRule)
 */
export interface ComplianceRuleNodeProperties {
  standard: 'FIPS 203' | 'FIPS 204' | 'FIPS 205' | 'NIST SP 800-218' | 'PCI-DSS v4.0' | 'SOC 2';
  ruleId: string; // Ex: 'PW.4.1', 'REQ-6.3.2'
  category: string;
  description: string;
  mandatoryStatus: 'MANDATORY' | 'RECOMMENDED' | 'OPTIONAL';
}

export interface ComplianceRuleNode {
  id: string; // Ex: 'rule_fips204'
  label: 'ComplianceRule';
  name: string; // Ex: 'FIPS 204 (ML-DSA PQC Digital Signatures)'
  riskLevel: RiskSeverity;
  properties: ComplianceRuleNodeProperties;
}

/**
 * Nó representando um Pacote do Inventário de Software / Supply Chain (:SBOMPackage)
 */
export interface SBOMPackageNodeProperties {
  packageName: string;
  version: string;
  license: string;
  ecosystem: 'cargo' | 'npm' | 'crates.io' | 'go' | 'pip';
  isDirectDependency: boolean;
  purl?: string;
}

export interface SBOMPackageNode {
  id: string; // Ex: 'sbom_solana_program'
  label: 'SBOMPackage';
  name: string; // Ex: 'solana-program@1.18.11'
  riskLevel: RiskSeverity;
  properties: SBOMPackageNodeProperties;
}

/**
 * União discriminada de todos os nós suportados pela Ontologia do Grafo
 */
export type SecurityGraphNode =
  | CodeFileNode
  | ASTFunctionNode
  | CryptoAlgorithmNode
  | VulnerabilityNode
  | ComplianceRuleNode
  | SBOMPackageNode;

// ============================================================================
// 3. INTERFACES DE RELACIONAMENTOS (ARESTAS CYPHER)
// ============================================================================

export interface SecurityGraphEdge<TProps extends Record<string, any> = Record<string, any>> {
  id: string;
  sourceId: string;
  targetId: string;
  type: RelationshipType;
  properties?: TProps;
}

export type CallsEdge = SecurityGraphEdge<{ line?: number; isAsync?: boolean }>;
export type UsesCryptoEdge = SecurityGraphEdge<{ purpose?: string; isHardwareAccelerated?: boolean }>;
export type ViolatesRuleEdge = SecurityGraphEdge<{ detectedAt?: string; severityOverride?: RiskSeverity }>;
export type DependsOnEdge = SecurityGraphEdge<{ isDevDependency?: boolean }>;
export type HasVulnerabilityEdge = SecurityGraphEdge<{ confirmed?: boolean; cvssOverride?: number }>;
export type AffectsModuleEdge = SecurityGraphEdge<{ impactScore?: number }>;
export type CompliesWithEdge = SecurityGraphEdge<{ verifiedAt?: string; proofUrl?: string }>;

export type SecurityGraphRelationship =
  | CallsEdge
  | UsesCryptoEdge
  | ViolatesRuleEdge
  | DependsOnEdge
  | HasVulnerabilityEdge
  | AffectsModuleEdge
  | CompliesWithEdge;

// ============================================================================
// 4. ESTRUTURA GLOBAL DO KNOWLEDGE GRAPH & SCHEMAS DDL NEO4J
// ============================================================================

export interface Neo4jKnowledgeGraphSchema {
  version: string;
  nodes: SecurityGraphNode[];
  relationships: SecurityGraphRelationship[];
  metadata: {
    generatedAt: string;
    totalNodes: number;
    totalRelationships: number;
    graphDensity: number;
  };
}

/**
 * DDLs de Índices e Restrições para o Neo4j / Memgraph / FalkorDB
 */
export const NEO4J_CYPHER_SCHEMA_STATEMENTS: string[] = [
  '// === RESTRIÇÕES DE UNICIDADE DA ONTOLOGIA (NEO4J DDL) ===',
  'CREATE CONSTRAINT codefile_id_unique IF NOT EXISTS FOR (f:CodeFile) REQUIRE f.id IS UNIQUE;',
  'CREATE CONSTRAINT astfunction_id_unique IF NOT EXISTS FOR (fn:ASTFunction) REQUIRE fn.id IS UNIQUE;',
  'CREATE CONSTRAINT cryptoalgo_id_unique IF NOT EXISTS FOR (c:CryptoAlgorithm) REQUIRE c.id IS UNIQUE;',
  'CREATE CONSTRAINT vuln_id_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE;',
  'CREATE CONSTRAINT compliance_id_unique IF NOT EXISTS FOR (cr:ComplianceRule) REQUIRE cr.id IS UNIQUE;',
  'CREATE CONSTRAINT sbompackage_id_unique IF NOT EXISTS FOR (sp:SBOMPackage) REQUIRE sp.id IS UNIQUE;',
  '',
  '// === ÍNDICES DE PERFORMANCE E BUSCA EM GRAFO ===',
  'CREATE INDEX codefile_filepath_idx IF NOT EXISTS FOR (f:CodeFile) ON (f.filePath);',
  'CREATE INDEX astfunction_name_idx IF NOT EXISTS FOR (fn:ASTFunction) ON (fn.functionName);',
  'CREATE INDEX vuln_severity_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity);',
  'CREATE INDEX compliance_standard_idx IF NOT EXISTS FOR (cr:ComplianceRule) ON (cr.standard);',
  'CREATE INDEX sbom_purl_idx IF NOT EXISTS FOR (sp:SBOMPackage) ON (sp.purl);',
];

// ============================================================================
// 5. HELPER FACTORIES PARA CRIAÇÃO DE NÓS E ARESTAS TIPADAS
// ============================================================================

export class GraphSchemaBuilder {
  public static createCodeFileNode(
    id: string,
    name: string,
    properties: CodeFileNodeProperties,
    riskLevel: RiskSeverity = 'SAFE'
  ): CodeFileNode {
    return { id, label: 'CodeFile', name, riskLevel, properties };
  }

  public static createASTFunctionNode(
    id: string,
    name: string,
    properties: ASTFunctionNodeProperties,
    riskLevel: RiskSeverity = 'LOW'
  ): ASTFunctionNode {
    return { id, label: 'ASTFunction', name, riskLevel, properties };
  }

  public static createVulnerabilityNode(
    id: string,
    name: string,
    properties: VulnerabilityNodeProperties,
    riskLevel: RiskSeverity = 'HIGH'
  ): VulnerabilityNode {
    return { id, label: 'Vulnerability', name, riskLevel, properties };
  }

  public static createComplianceRuleNode(
    id: string,
    name: string,
    properties: ComplianceRuleNodeProperties,
    riskLevel: RiskSeverity = 'CRITICAL'
  ): ComplianceRuleNode {
    return { id, label: 'ComplianceRule', name, riskLevel, properties };
  }

  public static createRelationship<TProps extends Record<string, any>>(
    sourceId: string,
    targetId: string,
    type: RelationshipType,
    properties?: TProps
  ): SecurityGraphEdge<TProps> {
    return {
      id: `${sourceId}-[:${type}]->${targetId}`,
      sourceId,
      targetId,
      type,
      properties,
    };
  }
}
