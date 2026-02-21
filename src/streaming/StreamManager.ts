// ============================================
// STREAM MANAGER - Skillmine Connectors SDK
// ============================================

import { EventEmitter } from 'events'

export interface StreamOptions {
  batchSize?: number        // items per batch
  intervalMs?: number       // polling interval
  maxItems?: number         // stop after N items
  onError?: (error: Error) => void
}

export interface StreamBatch<T> {
  items: T[]
  batchNumber: number
  isLast: boolean
  timestamp: Date
}

// ============================================
// Stream Manager
// ============================================

export class StreamManager extends EventEmitter {
  private activeStreams: Map<string, boolean> = new Map()

  // ============================================
  // Create Stream from Paginated API
  // ============================================

  async *createStream<T>(
    fetchFn: (page: number, limit: number) => Promise<{
      data: T[]
      hasMore: boolean
    }>,
    options?: StreamOptions,
  ): AsyncGenerator<StreamBatch<T>> {
    const batchSize = options?.batchSize ?? 50
    const maxItems = options?.maxItems ?? Infinity
    let page = 1
    let totalFetched = 0
    let batchNumber = 0

    while (true) {
      try {
        const result = await fetchFn(page, batchSize)
        batchNumber++
        totalFetched += result.data.length

        const isLast = !result.hasMore || totalFetched >= maxItems

        yield {
          items: result.data,
          batchNumber,
          isLast,
          timestamp: new Date(),
        }

        if (isLast) break
        page++

        if (options?.intervalMs) {
          await this.sleep(options.intervalMs)
        }
      } catch (error) {
        options?.onError?.(
          error instanceof Error ? error : new Error(String(error)),
        )
        break
      }
    }
  }

  // ============================================
  // Poll Stream (real-time polling)
  // ============================================

  async startPolling<T>(
    streamId: string,
    fetchFn: () => Promise<T[]>,
    onData: (items: T[]) => void,
    options?: { intervalMs?: number; onError?: (error: Error) => void },
  ): Promise<void> {
    this.activeStreams.set(streamId, true)
    const intervalMs = options?.intervalMs ?? 30000

    while (this.activeStreams.get(streamId)) {
      try {
        const items = await fetchFn()
        if (items.length > 0) {
          onData(items)
          this.emit('data', { streamId, items })
        }
      } catch (error) {
        options?.onError?.(
          error instanceof Error ? error : new Error(String(error)),
        )
      }
      await this.sleep(intervalMs)
    }
  }

  stopPolling(streamId: string): void {
    this.activeStreams.set(streamId, false)
    this.activeStreams.delete(streamId)
  }

  stopAllStreams(): void {
    for (const key of this.activeStreams.keys()) {
      this.activeStreams.set(key, false)
    }
    this.activeStreams.clear()
  }

  // ============================================
  // Batch Processor
  // ============================================

  async processBatches<T, R>(
    items: T[],
    processFn: (batch: T[]) => Promise<R[]>,
    batchSize = 100,
  ): Promise<R[]> {
    const results: R[] = []

    for (let i = 0; i < items.length; i += batchSize) {
      const batch = items.slice(i, i + batchSize)
      const batchResults = await processFn(batch)
      results.push(...batchResults)
    }

    return results
  }

  getActiveStreams(): string[] {
    return Array.from(this.activeStreams.keys())
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms))
  }
}

// ============================================
// Global Stream Manager
// ============================================

export const streamManager = new StreamManager()