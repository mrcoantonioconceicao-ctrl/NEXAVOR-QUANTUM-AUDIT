export interface DomainEvent {
  id: string;
  eventType: string;
  timestamp: string;
  aggregateId: string;
  payload: Record<string, any>;
}

export interface CodeRefactoredEvent extends DomainEvent {
  eventType: 'CodeRefactoredEvent';
  payload: {
    filePath: string;
    sourceLanguage: string;
    targetMode: 'MIGRATE_RUST' | 'MIGRATE_GO' | 'REFRACTOR_IN_PLACE' | 'IN_PLACE';
    targetLanguage: string;
    astFixesCount: number;
    hoursSaved: number;
    refactoredHash: string;
    ragStandardsApplied: string[];
  };
}

export interface VulnerabilityMitigatedEvent extends DomainEvent {
  eventType: 'VulnerabilityMitigatedEvent';
  payload: {
    vulnerabilityId: string;
    filePath: string;
    cwe: string;
    severity: string;
    mitigationStrategy: string;
    constantTimeVerified: boolean;
  };
}

type DomainEventHandler = (event: DomainEvent) => void;

class DomainEventPublisher {
  private handlers: Map<string, DomainEventHandler[]> = new Map();

  public subscribe(eventType: string, handler: DomainEventHandler): void {
    const existing = this.handlers.get(eventType) || [];
    this.handlers.set(eventType, [...existing, handler]);
  }

  public publish(event: DomainEvent): void {
    const eventHandlers = this.handlers.get(event.eventType) || [];
    eventHandlers.forEach((handler) => {
      try {
        handler(event);
      } catch (err) {
        console.error(`Error executing handler for domain event ${event.eventType}:`, err);
      }
    });
  }
}

export const eventPublisher = new DomainEventPublisher();
