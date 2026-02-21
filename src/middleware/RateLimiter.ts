// ============================================
// RATE LIMITER - Skillmine Connectors SDK
// ============================================

export interface RateLimitOptions {
  maxRequests: number      // max requests allowed
  perSeconds: number       // per N seconds window
  onThrottled?: (waitMs: number) => void
}

// ============================================
// Token Bucket Algorithm
// ============================================

export class RateLimiter {
  private tokens: number
  private lastRefillTime: number
  private readonly maxTokens: number
  private readonly refillRate: number   // tokens per ms
  private readonly onThrottled?: (waitMs: number) => void

  constructor(options: RateLimitOptions) {
    this.maxTokens = options.maxRequests
    this.tokens = options.maxRequests
    this.lastRefillTime = Date.now()
    this.refillRate = options.maxRequests / (options.perSeconds * 1000)
    this.onThrottled = options.onThrottled
  }

  // ============================================
  // Refill tokens based on elapsed time
  // ============================================

  private refill(): void {
    const now = Date.now()
    const elapsed = now - this.lastRefillTime
    const tokensToAdd = elapsed * this.refillRate
    this.tokens = Math.min(this.maxTokens, this.tokens + tokensToAdd)
    this.lastRefillTime = now
  }

  // ============================================
  // Acquire a token (wait if needed)
  // ============================================

  async acquire(): Promise<void> {
    this.refill()

    if (this.tokens >= 1) {
      this.tokens -= 1
      return
    }

    // Calculate wait time
    const tokensNeeded = 1 - this.tokens
    const waitMs = Math.ceil(tokensNeeded / this.refillRate)

    if (this.onThrottled) {
      this.onThrottled(waitMs)
    }

    await this.sleep(waitMs)
    this.refill()
    this.tokens -= 1
  }

  // ============================================
  // Check if request is allowed (non-blocking)
  // ============================================

  tryAcquire(): boolean {
    this.refill()
    if (this.tokens >= 1) {
      this.tokens -= 1
      return true
    }
    return false
  }

  // ============================================
  // Get current state
  // ============================================

  getState(): { tokens: number; maxTokens: number; utilization: number } {
    this.refill()
    return {
      tokens: Math.floor(this.tokens),
      maxTokens: this.maxTokens,
      utilization: ((this.maxTokens - this.tokens) / this.maxTokens) * 100,
    }
  }

  reset(): void {
    this.tokens = this.maxTokens
    this.lastRefillTime = Date.now()
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms))
  }
}

// ============================================
// Sliding Window Rate Limiter
// ============================================

export class SlidingWindowRateLimiter {
  private timestamps: number[] = []
  private readonly maxRequests: number
  private readonly windowMs: number

  constructor(options: RateLimitOptions) {
    this.maxRequests = options.maxRequests
    this.windowMs = options.perSeconds * 1000
  }

  async acquire(): Promise<void> {
    const now = Date.now()

    // Remove expired timestamps
    this.timestamps = this.timestamps.filter(
      (t) => now - t < this.windowMs,
    )

    if (this.timestamps.length >= this.maxRequests) {
      const waitMs = this.windowMs - (now - this.timestamps[0])
      await new Promise((resolve) => setTimeout(resolve, waitMs))
      return this.acquire()
    }

    this.timestamps.push(now)
  }

  getRemainingRequests(): number {
    const now = Date.now()
    this.timestamps = this.timestamps.filter(
      (t) => now - t < this.windowMs,
    )
    return Math.max(0, this.maxRequests - this.timestamps.length)
  }
}