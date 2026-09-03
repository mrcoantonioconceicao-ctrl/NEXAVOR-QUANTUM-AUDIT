/**
 * Bounded Context: knowledgeGraph
 * Definições da Ontologia Cypher para Neo4j / Memgraph / FalkorDB
 */

export class CypherOntology {
  /**
   * Scripts DDL de restrições e índices em Cypher
   */
  public static getSchemaDDL(): string[] {
    return [
      '// Constraints de Unicidade de Nós',
      'CREATE CONSTRAINT codefile_id_unique IF NOT EXISTS FOR (f:CodeFile) REQUIRE f.id IS UNIQUE;',
      'CREATE CONSTRAINT astfunction_id_unique IF NOT EXISTS FOR (fn:ASTFunction) REQUIRE fn.id IS UNIQUE;',
      'CREATE CONSTRAINT cryptoalgo_name_unique IF NOT EXISTS FOR (c:CryptoAlgorithm) REQUIRE c.name IS UNIQUE;',
      'CREATE CONSTRAINT vuln_id_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE;',
      'CREATE CONSTRAINT compliance_id_unique IF NOT EXISTS FOR (cr:ComplianceRule) REQUIRE cr.id IS UNIQUE;',
      'CREATE CONSTRAINT sbompackage_id_unique IF NOT EXISTS FOR (sp:SBOMPackage) REQUIRE sp.id IS UNIQUE;',
      '',
      '// Índices de Busca em Grafo',
      'CREATE INDEX codefile_name_idx IF NOT EXISTS FOR (f:CodeFile) ON (f.name);',
      'CREATE INDEX astfunction_name_idx IF NOT EXISTS FOR (fn:ASTFunction) ON (fn.name);',
      'CREATE INDEX vuln_severity_idx IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity);',
      'CREATE INDEX compliance_standard_idx IF NOT EXISTS FOR (cr:ComplianceRule) ON (cr.standard);',
    ];
  }

  /**
   * Consulta Cypher para Análise de Impacto Multi-Hop
   */
  public static getImpactTreeQuery(fileOrFunctionId: string, maxDepth: number = 3): string {
    return `
MATCH (start) WHERE start.id = "${fileOrFunctionId}" OR start.name = "${fileOrFunctionId}"
MATCH path = (start)-[*1..${maxDepth}]->(target)
RETURN path, 
       nodes(path) AS nodesInPath, 
       relationships(path) AS relsInPath,
       length(path) AS hopCount
ORDER BY hopCount ASC;
`.trim();
  }

  /**
   * Consulta Cypher para Criptografia Insegura e Violações de Conformidade
   */
  public static getPqcViolationsQuery(): string {
    return `
MATCH (f:CodeFile)-[:CALLS]->(fn:ASTFunction)-[:USES_CRYPTO]->(c:CryptoAlgorithm)-[:VIOLATES]->(cr:ComplianceRule)
OPTIONAL MATCH (f)-[:DEPENDS_ON]->(sp:SBOMPackage)-[:HAS_VULNERABILITY]->(v:Vulnerability)
RETURN f.name AS file, 
       fn.name AS function, 
       c.name AS algorithm, 
       cr.standard AS standardViolated, 
       cr.description AS ruleDescription,
       sp.name AS vulnerablePackage,
       v.id AS vulnId
ORDER BY cr.standard;
`.trim();
  }

  /**
   * Gerador de script Cypher MERGE completo para exportação e sincronização com Neo4j
   */
  public static generateCypherBatchImport(nodes: Array<any>, relationships: Array<any>): string {
    const lines: string[] = [];
    lines.push('// === SCRIPT CYPHER DE POVOAMENTO DO KNOWLEDGE GRAPH (NEXAVOR-QUANTUM-AUDIT) ===');
    lines.push('// Compatível com Neo4j Enterprise, Memgraph e FalkorDB\n');

    // Schema
    lines.push(...this.getSchemaDDL());
    lines.push('');

    // Criar Nós
    lines.push('// 1. Inserção de Nós (Entities)');
    for (const node of nodes) {
      const props = JSON.stringify(node.properties || {})
        .replace(/"([^"]+)":/g, '$1:') // Cypher key format
        .replace(/'/g, "\\'");
      lines.push(
        `MERGE (n:${node.label} {id: "${node.id}"}) SET n += ${props}, n.name = "${node.name}";`
      );
    }

    lines.push('\n// 2. Inserção de Arestas (Relationships)');
    for (const rel of relationships) {
      lines.push(
        `MATCH (a {id: "${rel.sourceId}"}), (b {id: "${rel.targetId}"}) MERGE (a)-[:${rel.type}]->(b);`
      );
    }

    return lines.join('\n');
  }
}
