// ============================================
// LOGGER - Complyment Connectors SDK
// ============================================

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  SILENT = 4,
}

export interface LogEntry {
  level: LogLevel
  message: string
  timestamp: Date
  connector?: string
  meta?: unknown
  traceId?: string
}

export interface LoggerOptions {
  level?: LogLevel
  connector?: string
  enableConsole?: boolean
  enableJson?: boolean
  onLog?: (entry: LogEntry) => void
}

// ============================================
// Logger Class
// ============================================

export class Logger {
  private level: LogLevel
  private connector?: string
  private enableConsole: boolean
  private enableJson: boolean
  private onLog?: (entry: LogEntry) => void
  private logs: LogEntry[] = []

  constructor(options?: LoggerOptions) {
    this.level = options?.level ?? LogLevel.INFO
    this.connector = options?.connector
    this.enableConsole = options?.enableConsole ?? true
    this.enableJson = options?.enableJson ?? false
    this.onLog = options?.onLog
  }

  // ============================================
  // Core Log Method
  // ============================================

  private log(
    level: LogLevel,
    message: string,
    meta?: unknown,
    traceId?: string,
  ): void {
    if (level < this.level) return

    const entry: LogEntry = {
      level,
      message,
      timestamp: new Date(),
      connector: this.connector,
      meta,
      traceId,
    }

    this.logs.push(entry)
    this.onLog?.(entry)

    if (this.enableConsole) {
      this.printToConsole(entry)
    }
  }

  // ============================================
  // Console Output
  // ============================================

  private printToConsole(entry: LogEntry): void {
    const levelName = LogLevel[entry.level]
    const connector = entry.connector ? `[${entry.connector}]` : ''
    const traceId = entry.traceId ? `[${entry.traceId}]` : ''
    const timestamp = entry.timestamp.toISOString()

    if (this.enableJson) {
      console.log(JSON.stringify({
        timestamp,
        level: levelName,
        connector: entry.connector,
        traceId: entry.traceId,
        message: entry.message,
        meta: entry.meta,
      }))
      return
    }

    const prefix = `${timestamp} ${levelName} ${connector}${traceId}`
    const output = entry.meta
      ? `${prefix} ${entry.message} ${JSON.stringify(entry.meta)}`
      : `${prefix} ${entry.message}`

    switch (entry.level) {
      case LogLevel.DEBUG: console.debug(output); break
      case LogLevel.INFO: console.info(output); break
      case LogLevel.WARN: console.warn(output); break
      case LogLevel.ERROR: console.error(output); break
    }
  }

  // ============================================
  // Public Methods
  // ============================================

  debug(message: string, meta?: unknown, traceId?: string): void {
    this.log(LogLevel.DEBUG, message, meta, traceId)
  }

  info(message: string, meta?: unknown, traceId?: string): void {
    this.log(LogLevel.INFO, message, meta, traceId)
  }

  warn(message: string, meta?: unknown, traceId?: string): void {
    this.log(LogLevel.WARN, message, meta, traceId)
  }

  error(message: string, meta?: unknown, traceId?: string): void {
    this.log(LogLevel.ERROR, message, meta, traceId)
  }

  // ============================================
  // Child Logger (for connector-specific)
  // ============================================

  child(connector: string): Logger {
    return new Logger({
      level: this.level,
      connector,
      enableConsole: this.enableConsole,
      enableJson: this.enableJson,
      onLog: this.onLog,
    })
  }

  // ============================================
  // Log History
  // ============================================

  getLogs(level?: LogLevel): LogEntry[] {
    if (level === undefined) return this.logs
    return this.logs.filter((l) => l.level === level)
  }

  clearLogs(): void {
    this.logs = []
  }

  setLevel(level: LogLevel): void {
    this.level = level
  }

  getStats() {
    return {
      total: this.logs.length,
      debug: this.logs.filter((l) => l.level === LogLevel.DEBUG).length,
      info: this.logs.filter((l) => l.level === LogLevel.INFO).length,
      warn: this.logs.filter((l) => l.level === LogLevel.WARN).length,
      error: this.logs.filter((l) => l.level === LogLevel.ERROR).length,
    }
  }
}

// ============================================
// Global Logger Instance
// ============================================

export const logger = new Logger({
  level: LogLevel.INFO,
  enableConsole: true,
})