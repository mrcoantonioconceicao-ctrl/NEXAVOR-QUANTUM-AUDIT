import React from 'react';
import { CheckCircle2, Clock, GitBranch } from 'lucide-react';
import { BpmnStep } from '../domain/types.ts';

interface BpmnWorkflowViewProps {
  steps: BpmnStep[];
}

export const BpmnWorkflowView: React.FC<BpmnWorkflowViewProps> = ({ steps }) => {
  return (
    <div className="space-y-6 max-w-7xl mx-auto px-4 sm:px-6 py-6 text-zinc-300">
      {/* Header Banner */}
      <div className="rounded border border-zinc-800 bg-zinc-900/40 p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <GitBranch className="h-4 w-4 text-emerald-400" />
            <span className="text-[10px] font-mono font-bold uppercase tracking-widest text-emerald-400">
              BPMN 2.0 EXECUTABLE WORKFLOW
            </span>
          </div>
          <h2 className="text-lg font-bold text-white font-mono uppercase">
            Pipeline Orquestrado de Auditoria & Governança
          </h2>
          <p className="text-xs text-zinc-400 max-w-3xl leading-relaxed">
            Estruturado segundo a especificação BPMN 2.0 com gateways de decisão determinísticos, swimlanes de segurança e isolamento de bounded contexts em SOA.
          </p>
        </div>
      </div>

      {/* BPMN Horizontal Workflow Diagram */}
      <div className="rounded border border-zinc-800 bg-zinc-950 p-6 overflow-x-auto shadow-xs">
        <div className="min-w-[840px] flex items-center justify-between gap-2 relative">
          {/* Connecting Line */}
          <div className="absolute top-1/2 left-8 right-8 h-0.5 bg-zinc-800 -translate-y-1/2 z-0" />

          {steps.map((step, idx) => {
            const isCompleted = step.status === 'COMPLETED';
            const isRunning = step.status === 'RUNNING';

            return (
              <div key={step.id} className="relative z-10 flex flex-col items-center text-center max-w-[140px]">
                {/* Node Box */}
                <div
                  className={`h-11 w-11 rounded flex items-center justify-center border transition-all ${
                    isCompleted
                      ? 'border-emerald-500 bg-emerald-500/10 text-emerald-400'
                      : isRunning
                      ? 'border-emerald-400 bg-zinc-900 text-emerald-400 animate-pulse'
                      : 'border-zinc-800 bg-zinc-900 text-zinc-600'
                  }`}
                >
                  {isCompleted ? (
                    <CheckCircle2 className="h-5 w-5" />
                  ) : isRunning ? (
                    <span className="h-4 w-4 border-2 border-emerald-400 border-t-transparent rounded-full animate-spin" />
                  ) : (
                    <Clock className="h-4 w-4" />
                  )}
                </div>

                {/* Step Title & Badge */}
                <div className="mt-3 space-y-1">
                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800 text-zinc-500 uppercase tracking-wider">
                    Passo {idx + 1}
                  </span>
                  <div className="text-xs font-bold text-zinc-200 line-clamp-2 font-mono">
                    {step.name.split('. ')[1] || step.name}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Detailed BPMN Swimlane Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {steps.map((step) => (
          <div
            key={step.id}
            className={`p-4 rounded border transition-all space-y-3 ${
              step.status === 'COMPLETED'
                ? 'border-zinc-800 bg-zinc-900/50'
                : step.status === 'RUNNING'
                ? 'border-emerald-500/60 bg-zinc-900'
                : 'border-zinc-800/60 bg-zinc-950/40 opacity-70'
            }`}
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-zinc-950 border border-zinc-800 text-zinc-400 uppercase tracking-wider font-bold">
                {step.role}
              </span>
              <span
                className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded uppercase tracking-wider ${
                  step.status === 'COMPLETED'
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    : step.status === 'RUNNING'
                    ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 animate-pulse'
                    : 'bg-zinc-900 text-zinc-600'
                }`}
              >
                {step.status}
              </span>
            </div>

            <div>
              <h4 className="text-xs font-bold text-white font-mono">{step.name}</h4>
              <p className="text-xs text-zinc-400 mt-1 leading-relaxed">{step.description}</p>
            </div>

            {/* Execution logs */}
            {step.details && step.details.length > 0 && (
              <div className="p-2.5 rounded bg-zinc-950 border border-zinc-800/80 text-[11px] font-mono text-zinc-400 space-y-1">
                {step.details.map((detail, dIdx) => (
                  <div key={dIdx} className="truncate">
                    <span className="text-zinc-600 mr-1.5">&gt;</span>
                    {detail}
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};
