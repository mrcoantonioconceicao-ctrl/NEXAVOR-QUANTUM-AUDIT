import type { Request, Response } from 'express';
import { generateExecutiveSecuritySvgBadge } from '../src/services/deterministicAuditEngine.ts';

export function handleBadgeSvg(req: Request, res: Response) {
  const repo = (req.query.repo as string) || 'RustShield Target';
  const scoreNum = parseInt((req.query.score as string) || '96', 10);
  const score = isNaN(scoreNum) ? 96 : scoreNum;
  const grade = (req.query.grade as string) || (score >= 90 ? 'A+' : score >= 80 ? 'A' : 'B');
  const pqc = req.query.pqc !== '0' && req.query.pqc !== 'false';
  const zk = req.query.zk === '1' || req.query.zk === 'true';

  const svg = generateExecutiveSecuritySvgBadge({
    repoName: repo,
    securityScore: score,
    grade,
    isPqcCompliant: pqc,
    isZkVerified: zk,
    standard: 'ISO 27001 / SOC 2',
  });

  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  return res.send(svg);
}

