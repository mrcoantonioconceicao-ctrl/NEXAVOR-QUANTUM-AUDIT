import { SecurityAuditReport } from '../domain/types.ts';

export function generateSarifJson(report: SecurityAuditReport): string {
  const rules = report.vulnerabilities.map((vuln) => ({
    id: vuln.cwe || vuln.id,
    name: vuln.title.replace(/[^a-zA-Z0-9]/g, '_'),
    shortDescription: {
      text: vuln.title,
    },
    fullDescription: {
      text: vuln.description,
    },
    help: {
      text: `Remediation Patch:\n\n${vuln.remediatedSnippet}\n\nUnsafe risk detail:\n${vuln.unsafeRiskDetail}`,
      markdown: `### Remediation Patch\n\`\`\`${(vuln.language || 'text').toLowerCase()}\n${vuln.remediatedSnippet}\n\`\`\`\n\n**Risk Detail:** ${vuln.unsafeRiskDetail}\n\n**CVSS Score:** ${vuln.cvssScore}`,
    },
    properties: {
      tags: ['security', vuln.category, vuln.language || 'polyglot'],
      precision: 'very-high',
      problem: {
        severity: vuln.severity === 'CRITICAL' ? 'error' : vuln.severity === 'HIGH' ? 'error' : 'warning',
      },
    },
  }));

  // Unique rules by id
  const uniqueRules = Array.from(new Map(rules.map((r) => [r.id, r])).values());

  const results = report.vulnerabilities.map((vuln) => ({
    ruleId: vuln.cwe || vuln.id,
    level: vuln.severity === 'CRITICAL' ? 'error' : vuln.severity === 'HIGH' ? 'error' : 'warning',
    message: {
      text: `${vuln.title}: ${vuln.description}`,
    },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: vuln.file,
            uriBaseId: '%SRCROOT%',
          },
          region: {
            startLine: vuln.line || 1,
            startColumn: 1,
          },
        },
      },
    ],
    fixes: [
      {
        description: {
          text: `Apply audited security remediation in ${vuln.language || 'source code'}`,
        },
        fileChanges: [
          {
            artifactLocation: {
              uri: vuln.file,
            },
            replacements: [
              {
                deletedRegion: {
                  startLine: vuln.line || 1,
                },
                insertedContent: {
                  text: vuln.remediatedSnippet,
                },
              },
            ],
          },
        ],
      },
    ],
  }));

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Q-Audit Universal Forensics & Quantum Shield',
            version: '2.5.0-PQC',
            informationUri: 'https://github.com/mit-quantum/q-audit',
            rules: uniqueRules,
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: report.timestamp,
          },
        ],
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

export function downloadSarifFile(report: SecurityAuditReport): void {
  const sarifStr = generateSarifJson(report);
  const blob = new Blob([sarifStr], { type: 'application/sarif+json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  const cleanName = report.targetRepo.name.replace(/[^a-zA-Z0-9_-]/g, '_');
  a.download = `q-audit-${cleanName}-${new Date().toISOString().slice(0, 10)}.sarif`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
