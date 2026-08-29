import React, { useEffect, useRef, useState } from 'react';
import { Radio, Activity, ShieldCheck, Zap } from 'lucide-react';
import { SecurityAuditReport } from '../domain/types.ts';

interface WaveTheoryVisualizerProps {
  report: SecurityAuditReport;
}

export const WaveTheoryVisualizer: React.FC<WaveTheoryVisualizerProps> = ({ report }) => {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [isDampenerActive, setIsDampenerActive] = useState(true);
  const [phaseOffset, setPhaseOffset] = useState(0.4);
  const [frequencyScale, setFrequencyScale] = useState(1.0);
  const [selectedHazardId, setSelectedHazardId] = useState<string | null>(
    report.waveHazards[0]?.id || null
  );

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let time = 0;

    const render = () => {
      time += 0.035;
      const width = canvas.width;
      const height = canvas.height;

      // Dark background (zinc-950)
      ctx.fillStyle = '#09090b';
      ctx.fillRect(0, 0, width, height);

      // Draw grid lines
      ctx.strokeStyle = '#27272a';
      ctx.lineWidth = 1;
      for (let x = 0; x < width; x += 40) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += 30) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }

      // Draw baseline center
      const centerY = height / 2;
      ctx.strokeStyle = '#3f3f46';
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(0, centerY);
      ctx.lineTo(width, centerY);
      ctx.stroke();
      ctx.setLineDash([]);

      // Draw Wave 1: CFG Control Flow Harmonic (Emerald)
      ctx.strokeStyle = '#10b981';
      ctx.lineWidth = 2;
      ctx.beginPath();
      for (let x = 0; x < width; x++) {
        const k1 = 0.018 * frequencyScale;
        const y = centerY + Math.sin(x * k1 + time) * 35;
        if (x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();

      // Draw Wave 2: Unsynchronized Async Memory Phase (Purple)
      ctx.strokeStyle = '#c084fc';
      ctx.lineWidth = 2;
      ctx.beginPath();
      for (let x = 0; x < width; x++) {
        const k2 = 0.024 * frequencyScale;
        const y = centerY + Math.sin(x * k2 - time * 0.8 + phaseOffset) * 40;
        if (x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();

      // Draw Superposition / Constructive Hazard Resonance
      ctx.lineWidth = 2.5;
      if (isDampenerActive) {
        ctx.strokeStyle = '#34d399'; // Soliton damped wave
      } else {
        ctx.strokeStyle = '#f87171'; // Uncontrolled Constructive Zero-Day resonance
      }

      ctx.beginPath();
      for (let x = 0; x < width; x++) {
        const k1 = 0.018 * frequencyScale;
        const k2 = 0.024 * frequencyScale;
        const w1 = Math.sin(x * k1 + time) * 35;
        const w2 = Math.sin(x * k2 - time * 0.8 + phaseOffset) * 40;

        let total = w1 + w2;
        if (isDampenerActive) {
          // Apply Soliton hyperbolic secant damping envelope: sech(x) = 1/cosh(x)
          const envelope = 1 / Math.cosh((x - width / 2) * 0.008);
          total = total * (0.35 + envelope * 0.25);
        }

        const y = centerY + total;
        if (x === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      }
      ctx.stroke();

      // Draw Resonant Shockwave Spikes if not damped
      if (!isDampenerActive) {
        for (let spike = 0; spike < 3; spike++) {
          const spikeX = (width * 0.25 + (time * 60 + spike * 180)) % width;
          ctx.fillStyle = 'rgba(248, 113, 113, 0.25)';
          ctx.beginPath();
          ctx.arc(spikeX, centerY, 24, 0, Math.PI * 2);
          ctx.fill();

          ctx.fillStyle = '#f87171';
          ctx.font = '10px monospace';
          ctx.fillText('0-DAY RESONANCE', spikeX - 45, centerY - 30);
        }
      }

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [isDampenerActive, phaseOffset, frequencyScale]);

  const selectedHazard =
    report.waveHazards.find((h) => h.id === selectedHazardId) || report.waveHazards[0];

  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6 text-zinc-300">
      {/* Header Banner */}
      <div className="rounded border border-zinc-800 bg-zinc-900/40 p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-emerald-400" />
            <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-emerald-400">
              TEORIA DAS ONDAS // MODELAGEM ESPECTRAL ZERO-DAY
            </span>
          </div>
          <h2 className="text-lg font-bold text-white font-mono uppercase">
            Interferência Harmônica & Amortecedores Soliton
          </h2>
          <p className="text-xs text-zinc-400 max-w-3xl leading-relaxed">
            Como ataques Zero-Day não possuem assinaturas prévias conhecidas, modelamos as transições de estado do código Rust como ondas de fase no espaço de Hilbert. Inconsistências de memória e desalinhamentos assíncronos geram ressonância construtiva de vulnerabilidade.
          </p>
        </div>

        <div className="shrink-0">
          <button
            onClick={() => setIsDampenerActive(!isDampenerActive)}
            className={`flex items-center gap-2 px-3.5 py-2 rounded font-mono text-[11px] font-bold uppercase tracking-wider transition-all shadow-xs ${
              isDampenerActive
                ? 'bg-zinc-100 text-zinc-950 hover:bg-white'
                : 'bg-red-500/20 border border-red-500/40 text-red-400 hover:bg-red-500/30 animate-pulse'
            }`}
          >
            <ShieldCheck className="h-3.5 w-3.5" />
            <span>{isDampenerActive ? 'Amortecedor: ATIVO' : 'Amortecedor: DESATIVADO'}</span>
          </button>
        </div>
      </div>

      {/* Interactive Oscilloscope Canvas */}
      <div className="rounded border border-zinc-800 bg-zinc-950 overflow-hidden shadow-xs">
        <div className="p-3 bg-zinc-900/70 border-b border-zinc-800 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5 text-emerald-400">
              <span className="h-2 w-2 rounded-full bg-emerald-400" />
              <span>Onda CFG: {report.editionDetected}</span>
            </div>
            <div className="flex items-center gap-1.5 text-purple-400">
              <span className="h-2 w-2 rounded-full bg-purple-400" />
              <span>Onda Memória Async</span>
            </div>
            <div className="flex items-center gap-1.5">
              <span
                className={`h-2 w-2 rounded-full ${
                  isDampenerActive ? 'bg-emerald-400' : 'bg-red-400'
                }`}
              />
              <span className={isDampenerActive ? 'text-emerald-400' : 'text-red-400'}>
                {isDampenerActive ? 'Superposição Segura (Soliton)' : 'Ressonância Crítica 0-Day'}
              </span>
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <span className="text-zinc-500">Fase (Δφ):</span>
              <input
                type="range"
                min="0"
                max="3.14"
                step="0.1"
                value={phaseOffset}
                onChange={(e) => setPhaseOffset(parseFloat(e.target.value))}
                className="w-20 accent-emerald-500"
              />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-zinc-500">Frequência:</span>
              <input
                type="range"
                min="0.5"
                max="2.5"
                step="0.2"
                value={frequencyScale}
                onChange={(e) => setFrequencyScale(parseFloat(e.target.value))}
                className="w-20 accent-emerald-500"
              />
            </div>
          </div>
        </div>

        <div className="relative">
          <canvas
            ref={canvasRef}
            width={1100}
            height={240}
            className="w-full h-[240px] block bg-zinc-950"
          />
        </div>
      </div>

      {/* Wave Theory Mathematical Foundation Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-xs">
        <div className="p-4 rounded border border-zinc-800 bg-zinc-900/50 border-l-2 border-l-emerald-500 space-y-2">
          <div className="flex items-center justify-between text-emerald-400 font-bold">
            <span className="text-[10px] uppercase tracking-wider">1. Entropia Espectral</span>
            <Activity className="h-4 w-4" />
          </div>
          <p className="text-zinc-400 font-sans text-xs">
            Equação de Shannon em espaço de transições:
          </p>
          <div className="p-2 rounded bg-zinc-950 border border-zinc-800/80 text-emerald-400 font-bold text-center">
            S = -\sum p_i \log_2(p_i)
          </div>
          <p className="text-zinc-500 text-[11px] font-sans leading-relaxed">
            Mede a desordem em blocos de memória insegura e saltos indiretos.
          </p>
        </div>

        <div className="p-4 rounded border border-zinc-800 bg-zinc-900/50 border-l-2 border-l-purple-500 space-y-2">
          <div className="flex items-center justify-between text-purple-400 font-bold">
            <span className="text-[10px] uppercase tracking-wider">2. Amplitude 0-Day</span>
            <Zap className="h-4 w-4" />
          </div>
          <p className="text-zinc-400 font-sans text-xs">
            Interferência construtiva de falhas:
          </p>
          <div className="p-2 rounded bg-zinc-950 border border-zinc-800/80 text-purple-300 font-bold text-center">
            A_res = \sqrt{`{A_1^2 + A_2^2 + 2 A_1 A_2 \cos(\Delta \phi)}`}
          </div>
          <p className="text-zinc-500 text-[11px] font-sans leading-relaxed">
            Quando \Delta \phi \approx 0, o risco de exploração atinge o pico construtivo.
          </p>
        </div>

        <div className="p-4 rounded border border-zinc-800 bg-zinc-900/50 border-l-2 border-l-blue-500 space-y-2">
          <div className="flex items-center justify-between text-blue-400 font-bold">
            <span className="text-[10px] uppercase tracking-wider">3. Amortecedor Soliton</span>
            <ShieldCheck className="h-4 w-4" />
          </div>
          <p className="text-zinc-400 font-sans text-xs">
            Onda não dispersiva de isolamento de estado:
          </p>
          <div className="p-2 rounded bg-zinc-950 border border-zinc-800/80 text-blue-300 font-bold text-center">
            \psi(x,t) = A \cdot \text{`sech`}(k(x - vt))
          </div>
          <p className="text-zinc-500 text-[11px] font-sans leading-relaxed">
            Garante que perturbações não se propaguem além dos limites da crate.
          </p>
        </div>
      </div>

      {/* Identified Wave Hazards Table */}
      <div className="rounded border border-zinc-800 bg-zinc-900/40 p-5 space-y-4">
        <div className="flex items-center justify-between border-b border-zinc-800/80 pb-3">
          <div className="flex items-center gap-2">
            <Radio className="h-4 w-4 text-purple-400" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-white font-mono">
              Vetores de Risco Espectral & Ondas de Choque Mapeadas ({report.waveHazards.length})
            </h3>
          </div>
        </div>

        {report.waveHazards.length === 0 ? (
          <div className="p-8 text-center text-zinc-500 text-xs font-mono">
            Nenhuma ressonância crítica de onda detectada. O código mantém invariantes estáveis de memória.
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {report.waveHazards.map((hazard) => (
              <div
                key={hazard.id}
                onClick={() => setSelectedHazardId(hazard.id)}
                className={`p-4 rounded border transition-all cursor-pointer space-y-2.5 ${
                  selectedHazard?.id === hazard.id
                    ? 'border-zinc-700 bg-zinc-900 shadow-xs'
                    : 'border-zinc-800 bg-zinc-900/40 hover:border-zinc-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-zinc-200 truncate max-w-[240px]">
                    {hazard.moduleName}
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-800 text-purple-400 border border-zinc-700">
                    Ressonância: {hazard.constructiveInterferenceScore}%
                  </span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                  <div className="p-1.5 rounded bg-zinc-950 border border-zinc-800/60 text-zinc-300">
                    <span className="text-zinc-500">Entropia: </span>
                    <span className="font-bold text-emerald-400">{(hazard.spectralEntropy * 100).toFixed(1)}%</span>
                  </div>
                  <div className="p-1.5 rounded bg-zinc-950 border border-zinc-800/60 text-zinc-300">
                    <span className="text-zinc-500">Raio: </span>
                    <span className="font-bold text-amber-400">{hazard.shockwaveBlastRadius}</span>
                  </div>
                </div>

                <div className="text-xs text-zinc-300">
                  <span className="font-bold text-red-400">Superfície Zero-Day: </span>
                  {hazard.theoreticalZeroDaySurface}
                </div>

                <div className="text-xs text-emerald-400 p-2.5 rounded bg-emerald-500/5 border border-emerald-500/20 font-mono">
                  <span className="font-bold">Amortecedor Soliton: </span>
                  {hazard.solitonDampenerRemediation}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
