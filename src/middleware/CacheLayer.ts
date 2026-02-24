// ============================================
// CACHE LAYER - Complyment Connectors SDK
// ============================================

export interface CacheOptions {
  ttl: number              // seconds
  maxSize?: number         // max entries
  onHit?: (key: string) => void
  onMiss?: (key: string) => void
  onEvict?: (key: string) => void
}

interface CacheEntry<T> {
  data: T
  expiresAt: number
  createdAt: number
  hits: number
}

// ============================================
// In-Memory Cache (LRU)
// ============================================

export class CacheLayer {
  private store: Map<string, CacheEntry<unknown>> = new Map()
  private readonly ttlMs: number
  private readonly maxSize: number
  private readonly onHit?: (key: string) => void
  private readonly onMiss?: (key: string) => void
  private readonly onEvict?: (key: string) => void

  // Stats
  private totalHits = 0
  private totalMisses = 0
  private totalSets = 0
  private totalEvictions = 0

  constructor(options: CacheOptions) {
    this.ttlMs = options.ttl * 1000
    this.maxSize = options.maxSize ?? 1000
    this.onHit = options.onHit
    this.onMiss = options.onMiss
    this.onEvict = options.onEvict
  }

  // ============================================
  // Get
  // ============================================

  get<T>(key: string): T | null {
    const entry = this.store.get(key) as CacheEntry<T> | undefined

    if (!entry) {
      this.totalMisses++
      this.onMiss?.(key)
      return null
    }

    if (Date.now() > entry.expiresAt) {
      this.store.delete(key)
      this.totalMisses++
      this.onMiss?.(key)
      return null
    }

    // Update hit count and move to end (LRU)
    entry.hits++
    this.store.delete(key)
    this.store.set(key, entry)

    this.totalHits++
    this.onHit?.(key)
    return entry.data
  }

  // ============================================
  // Set
  // ============================================

  set<T>(key: string, data: T, ttlSeconds?: number): void {
    // Evict if at max size
    if (this.store.size >= this.maxSize) {
      this.evictLRU()
    }

    const ttlMs = ttlSeconds ? ttlSeconds * 1000 : this.ttlMs

    this.store.set(key, {
      data,
      expiresAt: Date.now() + ttlMs,
      createdAt: Date.now(),
      hits: 0,
    })

    this.totalSets++
  }

  // ============================================
  // Get or Set (most useful pattern)
  // ============================================

  async getOrSet<T>(
    key: string,
    fetchFn: () => Promise<T>,
    ttlSeconds?: number,
  ): Promise<T> {
    const cached = this.get<T>(key)
    if (cached !== null) return cached

    const data = await fetchFn()
    this.set(key, data, ttlSeconds)
    return data
  }

  // ============================================
  // Delete
  // ============================================

  delete(key: string): boolean {
    return this.store.delete(key)
  }

  // ============================================
  // Clear
  // ============================================

  clear(): void {
    this.store.clear()
  }

  clearByPrefix(prefix: string): number {
    let count = 0
    for (const key of this.store.keys()) {
      if (key.startsWith(prefix)) {
        this.store.delete(key)
        count++
      }
    }
    return count
  }

  // ============================================
  // Has
  // ============================================

  has(key: string): boolean {
    const entry = this.store.get(key)
    if (!entry) return false
    if (Date.now() > entry.expiresAt) {
      this.store.delete(key)
      return false
    }
    return true
  }

  // ============================================
  // LRU Eviction
  // ============================================

  private evictLRU(): void {
    const firstKey = this.store.keys().next().value
    if (firstKey) {
      this.store.delete(firstKey)
      this.totalEvictions++
      this.onEvict?.(firstKey)
    }
  }

  // ============================================
  // Cleanup expired entries
  // ============================================

  cleanup(): number {
    const now = Date.now()
    let count = 0
    for (const [key, entry] of this.store.entries()) {
      if (now > entry.expiresAt) {
        this.store.delete(key)
        count++
      }
    }
    return count
  }

  // ============================================
  // Stats
  // ============================================

  getStats() {
    return {
      size: this.store.size,
      maxSize: this.maxSize,
      totalHits: this.totalHits,
      totalMisses: this.totalMisses,
      totalSets: this.totalSets,
      totalEvictions: this.totalEvictions,
      hitRate: this.totalHits + this.totalMisses > 0
        ? ((this.totalHits / (this.totalHits + this.totalMisses)) * 100).toFixed(2) + '%'
        : '0%',
    }
  }
}