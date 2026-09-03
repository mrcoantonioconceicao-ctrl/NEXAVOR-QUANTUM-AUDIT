/**
 * Bounded Context: knowledgeGraph
 * Tipos e Interfaces da Ontologia de Grafo de Conhecimento de Segurança e RAG Híbrido (Vector + GraphRAG)
 */

export type GraphNodeType = 
  | 'CodeFile' 
  | 'ASTFunction' 
  | 'CryptoAlgorithm' 
  | 'Vulnerability' 
  | 'ComplianceRule' 
  | 'SBOMPackage';

export type GraphRelationshipType = 
  | 'CALLS' 
  | 'USES_CRYPTO' 
  | 'VIOLATES' 
  | 'DEPENDS_ON' 
  | 'HAS_VULNERABILITY'
  | 'AFFECTS_MODULE'
  | 'COMPLIES_WITH';

export interface GraphNode {
  id: string;
  label: GraphNodeType;
  name: string;
  properties: Record<string, any>;
  riskLevel?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO' | 'SAFE';
}

export interface GraphRelationship {
  id: string;
  sourceId: string;
  targetId: string;
  type: GraphRelationshipType;
  properties?: Record<string, any>;
}

export interface SecurityKnowledgeGraph {
  nodes: GraphNode[];
  relationships: GraphRelationship[];
  updatedAt: string;
}

export interface MultiHopImpactNode {
  node: GraphNode;
  depth: number;
  parentPath: string[];
  relationshipToParent?: GraphRelationshipType;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  description: string;
}

export interface MultiHopImpactTree {
  rootNodeId: string;
  rootNodeName: string;
  maxDepth: number;
  impactedNodes: MultiHopImpactNode[];
  totalAffectedFunctions: number;
  totalVulnerabilitiesCount: number;
  nonComplianceRulesViolated: string[];
  affectedSbomPackages: string[];
  summaryText: string;
}

export interface VectorChunk {
  id: string;
  sourceDoc: string; // Ex: 'NIST SP 800-218', 'FIPS 204 (ML-DSA)', 'PCI-DSS v4.0', 'OSV.dev Advisory'
  title: string;
  content: string;
  category: 'NORMATIVE' | 'ADVISORY' | 'CODE_SNIPPET' | 'BEST_PRACTICE';
  similarityScore: number; // 0.0 - 1.0
  embeddingDim?: number[];
}

export interface GraphSubgraphResult {
  nodes: GraphNode[];
  relationships: GraphRelationship[];
  cypherMatchQuery: string;
  relevanceScore: number; // 0.0 - 1.0
  relationshipPathSummary: string[];
}

export interface HybridRAGQueryRequest {
  query: string;
  targetFileOrFunction?: string;
  vectorWeight?: number; // Default: 0.5
  graphWeight?: number;  // Default: 0.5
  topK?: number;         // Default: 5
}

export interface FusedContextItem {
  id: string;
  sourceType: 'VECTOR_SEMANTIC' | 'GRAPH_RELATIONAL';
  title: string;
  content: string;
  rawScore: number;
  rerankedScore: number;
  metadata: Record<string, any>;
}

export interface HybridRAGQueryResult {
  query: string;
  vectorResults: VectorChunk[];
  graphResult: GraphSubgraphResult;
  fusedContext: FusedContextItem[];
  contextPrompt: string;
  aiDiagnosticRationale?: string;
  metrics: {
    vectorRetrievalMs: number;
    graphRetrievalMs: number;
    fusionMs: number;
    totalMs: number;
    vectorCount: number;
    graphNodesCount: number;
    graphRelationshipsCount: number;
  };
}
