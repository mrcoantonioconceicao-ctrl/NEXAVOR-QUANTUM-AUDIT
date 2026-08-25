import express from 'express';
import path from 'path';
import dotenv from 'dotenv';
import { handleAnalyzeRepo, handleFetchGitHub, handleGetSystemMetrics } from './server/routes.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '15mb' }));

// Health check endpoint
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'online',
    version: '2.5.0-production',
    standards: ['DDD-Bounded-Context', 'SOA-Hexagonal', 'BPMN-2.0', 'Post-Quantum-ML-KEM', 'Wave-Theory-Soliton-ZeroDay'],
    environment: process.env.NODE_ENV || 'production',
    timestamp: new Date().toISOString(),
  });
});

// Real-time runtime telemetry metrics
app.get('/api/metrics', handleGetSystemMetrics);

// Real API Routes
app.post('/api/audit/analyze', handleAnalyzeRepo);
app.get('/api/github/repo', handleFetchGitHub);

// Serve static assets in production
const distPath = path.resolve(process.cwd(), 'dist');
app.use(express.static(distPath));

app.get('*', (_req, res) => {
  res.sendFile(path.join(distPath, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`[Q-Audit Production Security Server] Running on http://localhost:${PORT}`);
});
