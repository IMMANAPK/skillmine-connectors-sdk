// ============================================
// OPENTELEMETRY - Complyment Connectors SDK
// ============================================

export interface SpanOptions {
  name: string
  connector?: string
  method?: string
  url?: string
  attributes?: Record<string, string | number | boolean>
}

export interface Span {
  spanId: string
  traceId: string
  name: string
  startTime: Date
  endTime?: Date
  duration?: number
  status: 'ok' | 'error' | 'unset'
  attributes: Record<string, string | number | boolean>
  events: SpanEvent[]
  error?: Error
}

export interface SpanEvent {
  name: string
  timestamp: Date
  attributes?: Record<string, string | number | boolean>
}

export interface TelemetryOptions {
  serviceName?: string
  serviceVersion?: string
  enabled?: boolean
  onSpanEnd?: (span: Span) => void
  exportUrl?: string        // OTEL collector URL
}

// ============================================
// Simple Tracer (OTEL compatible structure)
// ============================================

export class Tracer {
  private spans: Map<string, Span> = new Map()
  private readonly serviceName: string
  private readonly serviceVersion: string
  private readonly enabled: boolean
  private readonly onSpanEnd?: (span: Span) => void

  constructor(options?: TelemetryOptions) {
    this.serviceName = options?.serviceName ?? 'complyment-connectors-sdk'
    this.serviceVersion = options?.serviceVersion ?? '1.0.0'
    this.enabled = options?.enabled ?? true
    this.onSpanEnd = options?.onSpanEnd
  }

  // ============================================
  // Start Span
  // ============================================

  startSpan(options: SpanOptions): string {
    if (!this.enabled) return 'disabled'

    const spanId = this.generateId()
    const traceId = this.generateId()

    const span: Span = {
      spanId,
      traceId,
      name: options.name,
      startTime: new Date(),
      status: 'unset',
      attributes: {
        'service.name': this.serviceName,
        'service.version': this.serviceVersion,
        ...(options.connector && { 'connector.name': options.connector }),
        ...(options.method && { 'http.method': options.method }),
        ...(options.url && { 'http.url': options.url }),
        ...options.attributes,
      },
      events: [],
    }

    this.spans.set(spanId, span)
    return spanId
  }

  // ============================================
  // End Span
  // ============================================

  endSpan(spanId: string, error?: Error): void {
    if (!this.enabled || spanId === 'disabled') return

    const span = this.spans.get(spanId)
    if (!span) return

    span.endTime = new Date()
    span.duration = span.endTime.getTime() - span.startTime.getTime()
    span.status = error ? 'error' : 'ok'

    if (error) {
      span.error = error
      span.attributes['error.message'] = error.message
      span.attributes['error.type'] = error.constructor.name
    }

    this.onSpanEnd?.(span)
    this.spans.delete(spanId)
  }

  // ============================================
  // Add Event to Span
  // ============================================

  addEvent(
    spanId: string,
    name: string,
    attributes?: Record<string, string | number | boolean>,
  ): void {
    if (!this.enabled || spanId === 'disabled') return

    const span = this.spans.get(spanId)
    if (!span) return

    span.events.push({
      name,
      timestamp: new Date(),
      attributes,
    })
  }

  // ============================================
  // Set Attribute
  // ============================================

  setAttribute(
    spanId: string,
    key: string,
    value: string | number | boolean,
  ): void {
    if (!this.enabled || spanId === 'disabled') return

    const span = this.spans.get(spanId)
    if (!span) return

    span.attributes[key] = value
  }

  // ============================================
  // Wrap Function with Span
  // ============================================

  async trace<T>(
    options: SpanOptions,
    fn: (spanId: string) => Promise<T>,
  ): Promise<T> {
    const spanId = this.startSpan(options)
    try {
      const result = await fn(spanId)
      this.endSpan(spanId)
      return result
    } catch (error) {
      this.endSpan(spanId, error instanceof Error ? error : new Error(String(error)))
      throw error
    }
  }

  // ============================================
  // Active Spans
  // ============================================

  getActiveSpans(): Span[] {
    return Array.from(this.spans.values())
  }

  // ============================================
  // Utility
  // ============================================

  private generateId(): string {
    return Math.random().toString(36).substring(2, 18) +
      Date.now().toString(36)
  }

  isEnabled(): boolean {
    return this.enabled
  }
}

// ============================================
// Global Tracer Instance
// ============================================

export const tracer = new Tracer({
  serviceName: 'complyment-connectors-sdk',
  enabled: true,
})