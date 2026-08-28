import type { Request, Response } from 'express';

export function handleBadgeSvg(req: Request, res: Response) {
  const repo = (req.query.repo as string) || 'Q-Audit Target';
  const scoreNum = parseInt((req.query.score as string) || '96', 10);
  const score = isNaN(scoreNum) ? 96 : scoreNum;
  const grade = (req.query.grade as string) || (score >= 90 ? 'A+' : score >= 80 ? 'A' : 'B');
  const pqc = req.query.pqc === '1' || req.query.pqc === 'true';

  const statusText = score >= 80 ? 'PASSED' : score >= 60 ? 'WARNING' : 'FAILED';
  const colorHex = score >= 90 ? '#00C853' : score >= 80 ? '#4CAF50' : score >= 70 ? '#FFC107' : '#F44336';
  const textValue = `${score}/100 ${statusText}${pqc ? ' • PQC' : ''}`;

  const svg = `
<svg xmlns="http://www.w3.org/2000/svg" width="220" height="28" role="img" aria-label="Q-Audit Security: ${textValue}">
  <title>Q-Audit Security Status: ${textValue}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="220" height="28" rx="4" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="105" height="28" fill="#18181b"/>
    <rect x="105" width="115" height="28" fill="${colorHex}"/>
    <rect width="220" height="28" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="11">
    <path fill="#00E676" d="M14 6l6 3v5c0 4.1-2.9 7.9-6 9-3.1-1.1-6-4.9-6-9V9l6-3z" transform="scale(0.8) translate(3, 2)"/>
    <text x="58" y="18" fill="#010101" fill-opacity=".3">Q-Audit Sec</text>
    <text x="58" y="17" fill="#fff">Q-Audit Sec</text>
    <text x="162" y="18" fill="#010101" fill-opacity=".3">${textValue}</text>
    <text x="162" y="17" fill="#fff">${textValue}</text>
  </g>
</svg>
  `.trim();

  res.setHeader('Content-Type', 'image/svg+xml');
  res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  return res.send(svg);
}
