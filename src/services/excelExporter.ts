import { SecurityAuditReport } from '../domain/types.ts';

/**
 * Serviço de Exportação para Excel / CSV de Relatórios de Compliance e Auditoria DevSecOps
 */

export function exportAuditToCsv(report: SecurityAuditReport): void {
  const headers = [
    'ID Vulnerabilidade',
    'Severidade',
    'Arquivo',
    'Linha',
    'Título / Regra',
    'Descrição',
    'Categoria CWE/OWASP',
    'Status Mitigação'
  ];

  const rows = (report.vulnerabilities || []).map((v) => [
    `"${v.id}"`,
    `"${v.severity}"`,
    `"${v.file || 'N/A'}"`,
    `"${v.line || 1}"`,
    `"${(v.title || '').replace(/"/g, '""')}"`,
    `"${(v.description || '').replace(/"/g, '""')}"`,
    `"${v.cwe || v.category || 'CWE-200'}"`,
    `"${v.miriVerificationStatus === 'VERIFIED_SAFE' || v.miriVerificationStatus === 'COMPLIANT' ? 'MITIGADO' : 'PENDENTE'}"`
  ]);

  const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');

  const blob = new Blob(['\uFEFF' + csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', `relatorio_audit_${report.id.slice(0, 8)}_${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

export function exportComplianceToCsv(report: SecurityAuditReport): void {
  const headers = [
    'Framework Compliance',
    'ID Requisito',
    'Controle',
    'Status Conformidade',
    'Pontuação',
    'Ação Recomendada'
  ];

  const frameworks = [
    { name: 'SOC 2 Type II', score: report.overallSecurityScore >= 80 ? 'CONFORME' : 'ATENÇÃO REQUERIDA' },
    { name: 'ISO/IEC 27001:2022', score: report.overallSecurityScore >= 75 ? 'CONFORME' : 'PARCIALMENTE CONFORME' },
    { name: 'NIST SP 800-218 (SSDF v1.1)', score: report.quantumMetrics?.quantumReadinessScore >= 80 ? 'CONFORME' : 'NÃO CONFORME' },
    { name: 'PCI-DSS v4.0', score: report.overallSecurityScore >= 85 ? 'CONFORME' : 'AUDITORIA PENDENTE' }
  ];

  const rows = frameworks.map((f, idx) => [
    `"${f.name}"`,
    `"REQ-00${idx + 1}"`,
    `"Segurança de Código e Gestão de Riscos Ciber"`,
    `"${f.score}"`,
    `"${report.overallSecurityScore}%"`,
    `"${f.score === 'CONFORME' ? 'Manter monitoramento contínuo' : 'Executar refatoração AST e autofix nas falhas críticas'}"`
  ]);

  const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');

  const blob = new Blob(['\uFEFF' + csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', `relatorio_compliance_${new Date().toISOString().slice(0, 10)}.csv`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
