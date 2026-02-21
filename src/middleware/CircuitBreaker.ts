// ============================================
// CIRCUIT BREAKER - Skillmine Connectors SDK
// ============================================

export type CircuitState = 'closed' | 'open' | 'half-open'

export interface CircuitBreakerOptions {
  failureThreshold?: number    // failures before opening
  successThreshold?: number    // successes to close from half-open
  recoveryTimeMs?: number      // time before half-open retry
  onStateChange?: (from: CircuitState, to: CircuitState) => void
  onFailure?: (error: Error, failures: number) => void
  onSuccess?: () => void
}

export interface CircuitBreakerStats {
  state: CircuitState
  failures: number
  successes: number
  totalRequests: number
  lastFailureTime?: Date
  lastStateChangeTime: Date
}

// ============================================
// Circuit Breaker Implementation
// ============================================

export class CircuitBreaker {
  private state: CircuitState = 'closed'
  private failures = 0
  private successes = 0
  private totalRequests = 0
  private lastFailureTime?: Date
  private lastStateChangeTime = new Date()

  private readonly failureThreshold: number
  private readonly successThreshold: number
  private readonly recoveryTimeMs: number
  private readonly onStateChange?: (from: CircuitState, to: CircuitState) => void
  private readonly onFailure?: (error: Error, failures: number) => void
  private readonly onSuccess?: () => void

  constructor(options?: CircuitBreakerOptions) {
    this.failureThreshold = options?.failureThreshold ?? 5
    this.successThreshold = options?.successThreshold ?? 2
    this.recoveryTimeMs = options?.recoveryTimeMs ?? 60000
    this.onStateChange = options?.onStateChange
    this.onFailure = options?.onFailure
    this.onSuccess = options?.onSuccess
  }

  // ============================================
  // Execute with Circuit Breaker
  // ============================================

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    this.totalRequests++

    if (this.state === 'open') {
      if (this.canAttemptReset()) {
        this.transitionTo('half-open')
      } else {
        throw new Error(
          `Circuit breaker is OPEN. Last failure: ${this.lastFailureTime?.toISOString()}`,
        )
      }
    }

    try {
      const result = await fn()
      this.recordSuccess()
      return result
    } catch (error) {
      this.recordFailure(error instanceof Error ? error : new Error(String(error)))
      throw error
    }
  }

  // ============================================
  // Record Success
  // ============================================

  private recordSuccess(): void {
    this.failures = 0
    this.successes++
    this.onSuccess?.()

    if (this.state === 'half-open' && this.successes >= this.successThreshold) {
      this.transitionTo('closed')
    }
  }

  // ============================================
  // Record Failure
  // ============================================

  private recordFailure(error: Error): void {
    this.failures++
    this.successes = 0
    this.lastFailureTime = new Date()
    this.onFailure?.(error, this.failures)

    if (
      this.state === 'closed' &&
      this.failures >= this.failureThreshold
    ) {
      this.transitionTo('open')
    } else if (this.state === 'half-open') {
      this.transitionTo('open')
    }
  }

  // ============================================
  // State Transition
  // ============================================

  private transitionTo(newState: CircuitState): void {
    const prevState = this.state
    this.state = newState
    this.lastStateChangeTime = new Date()

    if (newState === 'closed') {
      this.failures = 0
      this.successes = 0
    }

    this.onStateChange?.(prevState, newState)
  }

  // ============================================
  // Can Attempt Reset
  // ============================================

  private canAttemptReset(): boolean {
    if (!this.lastFailureTime) return true
    const elapsed = Date.now() - this.lastFailureTime.getTime()
    return elapsed >= this.recoveryTimeMs
  }

  // ============================================
  // Public API
  // ============================================

  getState(): CircuitState {
    return this.state
  }

  getStats(): CircuitBreakerStats {
    return {
      state: this.state,
      failures: this.failures,
      successes: this.successes,
      totalRequests: this.totalRequests,
      lastFailureTime: this.lastFailureTime,
      lastStateChangeTime: this.lastStateChangeTime,
    }
  }

  reset(): void {
    this.transitionTo('closed')
    this.totalRequests = 0
    this.lastFailureTime = undefined
  }

  isOpen(): boolean {
    return this.state === 'open'
  }

  isClosed(): boolean {
    return this.state === 'closed'
  }
}