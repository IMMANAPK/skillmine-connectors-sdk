// ============================================
// RETRY HANDLER - Skillmine Connectors SDK
// ============================================

export interface RetryOptions {
  maxRetries?: number
  initialDelayMs?: number
  maxDelayMs?: number
  backoffMultiplier?: number
  retryableStatusCodes?: number[]
  onRetry?: (attempt: number, error: Error) => void
}

const DEFAULT_OPTIONS: Required<RetryOptions> = {
  maxRetries: 3,
  initialDelayMs: 1000,
  maxDelayMs: 30000,
  backoffMultiplier: 2,
  retryableStatusCodes: [408, 429, 500, 502, 503, 504],
  onRetry: () => {},
}

// ============================================
// Exponential Backoff with Jitter
// ============================================

function calculateDelay(
  attempt: number,
  initialDelayMs: number,
  maxDelayMs: number,
  backoffMultiplier: number,
): number {
  const exponential = initialDelayMs * Math.pow(backoffMultiplier, attempt - 1)
  const jitter = Math.random() * 0.3 * exponential // 30% jitter
  return Math.min(exponential + jitter, maxDelayMs)
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

// ============================================
// Retry Wrapper
// ============================================

export async function withRetry<T>(
  fn: () => Promise<T>,
  options?: RetryOptions,
): Promise<T> {
  const opts = { ...DEFAULT_OPTIONS, ...options }
  let lastError: Error = new Error('Unknown error')

  for (let attempt = 1; attempt <= opts.maxRetries + 1; attempt++) {
    try {
      return await fn()
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error))

      const statusCode = (error as { statusCode?: number }).statusCode
      const isRetryable = statusCode
        ? opts.retryableStatusCodes.includes(statusCode)
        : true

      if (!isRetryable || attempt > opts.maxRetries) {
        throw lastError
      }

      const delay = calculateDelay(
        attempt,
        opts.initialDelayMs,
        opts.maxDelayMs,
        opts.backoffMultiplier,
      )

      opts.onRetry(attempt, lastError)
      await sleep(delay)
    }
  }

  throw lastError
}

// ============================================
// Retry Class (for stateful usage)
// ============================================

export class RetryHandler {
  private options: Required<RetryOptions>

  constructor(options?: RetryOptions) {
    this.options = { ...DEFAULT_OPTIONS, ...options }
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    return withRetry(fn, this.options)
  }

  updateOptions(options: Partial<RetryOptions>): void {
    this.options = { ...this.options, ...options }
  }
}