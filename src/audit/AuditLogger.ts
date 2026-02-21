// ============================================
// AUDIT LOGGER - Skillmine Connectors SDK
// ============================================

export type AuditAction =
  | 'connector.connect'
  | 'connector.disconnect'
  | 'data.fetch'
  | 'data.create'
  | 'data.update'
  | 'data.delete'
  | 'auth.login'
  | 'auth.logout'
  | 'auth.failed'
  | 'scan.launch'
  | 'scan.cancel'
  | 'threat.mitigate'
  | 'policy.change'
  | 'deployment.create'
  | 'deployment.cancel'

export type AuditStatus = 'success' | 'failure' | 'pending'

export interface AuditEntry {
  id: string
  action: AuditAction
  connector: string
  status: AuditStatus
  timestamp: Date
  duration?: number
  userId?: string
  resourceId?: string
  resourceType?: string
  details?: Record<string, unknown>
  error?: string
  ipAddress?: string
}

export interface AuditLoggerOptions {
  enabled?: boolean
  maxEntries?: number
  onEntry?: (entry: AuditEntry) => void
  storage?: 'memory' | 'custom'
}

// ============================================
// Audit Logger
// ============================================

export class AuditLogger {
  private entries: AuditEntry[] = []
  private readonly enabled: boolean
  private readonly maxEntries: number
  private readonly onEntry?: (entry: AuditEntry) => void

  constructor(options?: AuditLoggerOptions) {
    this.enabled = options?.enabled ?? true
    this.maxEntries = options?.maxEntries ?? 10000
    this.onEntry = options?.onEntry
  }

  // ============================================
  // Log Entry
  // ============================================

  log(entry: Omit<AuditEntry, 'id' | 'timestamp'>): AuditEntry {
    if (!this.enabled) {
      return { ...entry, id: 'disabled', timestamp: new Date() }
    }

    const auditEntry: AuditEntry = {
      ...entry,
      id: this.generateId(),
      timestamp: new Date(),
    }

    // Rotate if at max
    if (this.entries.length >= this.maxEntries) {
      this.entries.shift()
    }

    this.entries.push(auditEntry)
    this.onEntry?.(auditEntry)

    return auditEntry
  }

  // ============================================
  // Convenience Methods
  // ============================================

  logSuccess(
    action: AuditAction,
    connector: string,
    details?: Record<string, unknown>,
    duration?: number,
  ): AuditEntry {
    return this.log({
      action,
      connector,
      status: 'success',
      details,
      duration,
    })
  }

  logFailure(
    action: AuditAction,
    connector: string,
    error: string,
    details?: Record<string, unknown>,
  ): AuditEntry {
    return this.log({
      action,
      connector,
      status: 'failure',
      error,
      details,
    })
  }

  logDataFetch(
    connector: string,
    resourceType: string,
    resourceId?: string,
    duration?: number,
  ): AuditEntry {
    return this.log({
      action: 'data.fetch',
      connector,
      status: 'success',
      resourceType,
      resourceId,
      duration,
    })
  }

  // ============================================
  // Query
  // ============================================

  getEntries(filter?: {
    connector?: string
    action?: AuditAction
    status?: AuditStatus
    from?: Date
    to?: Date
    limit?: number
  }): AuditEntry[] {
    let results = [...this.entries]

    if (filter?.connector) {
      results = results.filter((e) => e.connector === filter.connector)
    }
    if (filter?.action) {
      results = results.filter((e) => e.action === filter.action)
    }
    if (filter?.status) {
      results = results.filter((e) => e.status === filter.status)
    }
    if (filter?.from) {
      results = results.filter((e) => e.timestamp >= filter.from!)
    }
    if (filter?.to) {
      results = results.filter((e) => e.timestamp <= filter.to!)
    }
    if (filter?.limit) {
      results = results.slice(-filter.limit)
    }

    return results.sort((a, b) =>
      b.timestamp.getTime() - a.timestamp.getTime(),
    )
  }

  getFailures(connector?: string): AuditEntry[] {
    return this.getEntries({ status: 'failure', connector })
  }

  getRecentEntries(limit = 50): AuditEntry[] {
    return this.getEntries({ limit })
  }

  // ============================================
  // Stats
  // ============================================

  getStats(connector?: string) {
    const entries = connector
      ? this.entries.filter((e) => e.connector === connector)
      : this.entries

    const successCount = entries.filter((e) => e.status === 'success').length
    const failureCount = entries.filter((e) => e.status === 'failure').length
    const avgDuration = entries
      .filter((e) => e.duration !== undefined)
      .reduce((sum, e) => sum + (e.duration ?? 0), 0) /
      (entries.filter((e) => e.duration !== undefined).length || 1)

    return {
      total: entries.length,
      success: successCount,
      failure: failureCount,
      successRate: entries.length > 0
        ? ((successCount / entries.length) * 100).toFixed(2) + '%'
        : '0%',
      avgDurationMs: Math.round(avgDuration),
    }
  }

  // ============================================
  // Export
  // ============================================

  exportAsJson(): string {
    return JSON.stringify(this.entries, null, 2)
  }

  exportAsCsv(): string {
    const headers = [
      'id', 'action', 'connector', 'status',
      'timestamp', 'duration', 'resourceType', 'error',
    ]
    const rows = this.entries.map((e) => [
      e.id, e.action, e.connector, e.status,
      e.timestamp.toISOString(), e.duration ?? '',
      e.resourceType ?? '', e.error ?? '',
    ])

    return [
      headers.join(','),
      ...rows.map((r) => r.join(',')),
    ].join('\n')
  }

  clear(): void {
    this.entries = []
  }

  // ============================================
  // Utility
  // ============================================

  private generateId(): string {
    return `audit_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`
  }
}

// ============================================
// Global Audit Logger
// ============================================

export const auditLogger = new AuditLogger({ enabled: true })