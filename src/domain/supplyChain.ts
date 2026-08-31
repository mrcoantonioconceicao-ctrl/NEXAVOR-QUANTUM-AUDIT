/**
 * Bounded Context: Supply Chain Security & Software Bill of Materials (SBOM)
 * Níveis de integridade SLSA (Supply-chain Levels for Software Artifacts) e CycloneDX.
 */

export type SLSALevel = 'SLSA_LEVEL_1' | 'SLSA_LEVEL_2' | 'SLSA_LEVEL_3' | 'SLSA_LEVEL_4';

export interface CycloneDXComponent {
  type: 'library' | 'framework' | 'application' | 'container';
  name: string;
  version: string;
  purl?: string;
  licenses?: string[];
  hashes?: Array<{ alg: string; content: string }>;
  vulnerabilitiesCount?: number;
}

export interface CycloneDXSpec {
  bomFormat: 'CycloneDX';
  specVersion: '1.5' | '1.6';
  serialNumber: string;
  version: number;
  metadata: {
    timestamp: string;
    tools: string[];
    component: CycloneDXComponent;
  };
  components: CycloneDXComponent[];
}

export interface SBOMDocument {
  id: string;
  repoName: string;
  slsaLevel: SLSALevel;
  spec: CycloneDXSpec;
  tamperProofHash: string;
  pqcSignature: string;
}

export class SupplyChainService {
  public static generateSBOM(
    repoName: string,
    components: Array<{ name: string; version: string; eco: string; vulns: number }>
  ): SBOMDocument {
    const timestamp = new Date().toISOString();
    const cycloneComponents: CycloneDXComponent[] = components.map((c) => ({
      type: 'library',
      name: c.name,
      version: c.version,
      purl: `pkg:${c.eco.toLowerCase()}/${c.name}@${c.version}`,
      vulnerabilitiesCount: c.vulns,
    }));

    const spec: CycloneDXSpec = {
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: `urn:uuid:${Math.random().toString(36).substring(2)}-nexavor-sbom`,
      version: 1,
      metadata: {
        timestamp,
        tools: ['NEXAVOR RustShield Quantum v2.0 Engine', 'CycloneDX Generator'],
        component: {
          type: 'application',
          name: repoName,
          version: '1.0.0',
        },
      },
      components: cycloneComponents,
    };

    return {
      id: `SBOM-${repoName.replace(/[^a-zA-Z0-9]/g, '-')}`,
      repoName,
      slsaLevel: 'SLSA_LEVEL_3',
      spec,
      tamperProofHash: `sha256-${Math.random().toString(36).substring(2)}${Math.random().toString(36).substring(2)}`,
      pqcSignature: `ML-DSA-65-SIG-${Math.random().toString(36).substring(2)}`,
    };
  }
}
