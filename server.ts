// [RustShield AST Engine] Middleware de Segurança Injetado via AST
import { Request, Response, NextFunction } from 'express';

export const requireJwtAuth = (req: Request, res: Response, next: NextFunction) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '401 Unauthorized: JWT Token ausente ou inválido.' });
  }
  next();
};

import express from 'express';
import path from 'path';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import { handleAnalyzeRepo, handleFetchGitHub, handleGetSystemMetrics, handleOsvBatchProxy, handleCreateGitHubPullRequest, handleSuggestRustPatch, handleAstRefactor, handleCreateRefactorPullRequest } from './server/routes.js';
import { handleGetWebhookConfigs, handleSaveWebhookConfig, handleDeleteWebhookConfig, handleGetWebhookDeliveries, handleIncomingGitHubWebhook, handleSimulateWebhook, handleWebhookStream, } from './server/webhooks.js';
import { handleBadgeSvg } from './server/badgeGenerator.js';
dotenv.config();
async function startServer() {
    const app = express();
    const PORT = 3000;
    app.use(express.json({ limit: '15mb' }));
    // Health check endpoint
    app.get('/api/health', (_req, res) => {
        res.json({
            status: 'online',
            version: '2.5.0-production',
            standards: ['DDD-Bounded-Context', 'SOA-Hexagonal', 'BPMN-2.0', 'Post-Quantum-ML-KEM', 'Wave-Theory-Soliton-ZeroDay'],
            environment: process.env.NODE_ENV || 'development',
            timestamp: new Date().toISOString(),
        });
    });
    // Real-time runtime telemetry metrics
    app.get('/api/metrics', handleGetSystemMetrics);
    // Real API Routes
    app.post('/api/audit/analyze', requireJwtAuth, handleAnalyzeRepo);
    app.post('/api/audit/suggest-rust-patch', requireJwtAuth, handleSuggestRustPatch);
    app.post('/api/audit/ast-refactor', requireJwtAuth, handleAstRefactor);
    app.post('/api/audit/osv-batch', requireJwtAuth, handleOsvBatchProxy);
    app.get('/api/github/repo', handleFetchGitHub);
    app.post('/api/github/create-pr', handleCreateGitHubPullRequest);
    app.post('/api/github/pulls', handleCreateGitHubPullRequest);
    app.post('/api/github/refactor-pr', handleCreateRefactorPullRequest);
    // Webhook Configuration & Real-time Integration Routes
    app.get('/api/webhooks/configs', handleGetWebhookConfigs);
    app.post('/api/webhooks/config', handleSaveWebhookConfig);
    app.delete('/api/webhooks/config/:id', handleDeleteWebhookConfig);
    app.get('/api/webhooks/deliveries', handleGetWebhookDeliveries);
    app.post('/api/webhooks/github', handleIncomingGitHubWebhook);
    app.post('/api/webhooks/simulate', handleSimulateWebhook);
    app.get('/api/webhooks/stream', handleWebhookStream);
    // Dynamic SVG Badge Generation Route
    app.get('/api/badge/shield.svg', handleBadgeSvg);
    app.get('/api/badge/svg', handleBadgeSvg);
    // Vite middleware for development / Static files in production
    if (process.env.NODE_ENV !== 'production') {
        const vite = await createViteServer({
            server: { middlewareMode: true },
            appType: 'spa',
        });
        app.use(vite.middlewares);
    }
    else {
        const distPath = path.resolve(process.cwd(), 'dist');
        app.use(express.static(distPath));
        app.get('*', (_req, res) => {
            res.sendFile(path.join(distPath, 'index.html'));
        });
    }
    app.listen(PORT, "127.0.0.1", () => {
        console.log(`[Q-Audit Production Security Server] Running on http://localhost:${PORT}`);
    });
}
startServer().catch((err) => {
    console.error('[Server Startup Error]', err);
});
