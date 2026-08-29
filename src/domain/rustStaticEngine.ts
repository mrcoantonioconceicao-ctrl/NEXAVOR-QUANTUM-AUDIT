import { RustEdition, RustVulnerability, SourceFile } from './types.ts';
import { analyzePolyglotStaticPatterns } from './polyglotStaticEngine.ts';

export function analyzeRustStaticPatterns(files: SourceFile[]): {
  vulnerabilities: RustVulnerability[];
  editionDetected: RustEdition;
  totalUnsafeBlocks: number;
  totalLines: number;
  detectedLanguages?: string[];
  primaryLanguage?: string;
} {
  const result = analyzePolyglotStaticPatterns(files);
  return {
    vulnerabilities: result.vulnerabilities,
    editionDetected: result.editionDetected,
    totalUnsafeBlocks: result.totalUnsafeBlocks,
    totalLines: result.totalLines,
    detectedLanguages: result.detectedLanguages,
    primaryLanguage: result.primaryLanguage,
  };
}
