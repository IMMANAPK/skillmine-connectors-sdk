// ============================================
// CONNECTOR REGISTRY - Skillmine Connectors SDK
// ============================================

import { BaseConnector } from './BaseConnector'
import { HealthCheckResult } from './types'
import { PluginNotFoundError, DuplicatePluginError } from './errors'

// ============================================
// Registry
// ============================================

export class ConnectorRegistry {
  private connectors: Map<string, BaseConnector> = new Map()

  // ============================================
  // Register
  // ============================================

  register(name: string, connector: BaseConnector): void {
    if (this.connectors.has(name)) {
      throw new DuplicatePluginError(name)
    }
    this.connectors.set(name, connector)
  }

  // ============================================
  // Get
  // ============================================

  get<T extends BaseConnector>(name: string): T {
    const connector = this.connectors.get(name)
    if (!connector) throw new PluginNotFoundError(name)
    return connector as T
  }

  has(name: string): boolean {
    return this.connectors.has(name)
  }

  unregister(name: string): void {
    this.connectors.delete(name)
  }

  // ============================================
  // Health Check All
  // ============================================

  async healthCheckAll(): Promise<Record<string, HealthCheckResult>> {
    const results: Record<string, HealthCheckResult> = {}

    await Promise.all(
      Array.from(this.connectors.entries()).map(async ([name, connector]) => {
        results[name] = await connector.healthCheck()
      }),
    )

    return results
  }

  // ============================================
  // List
  // ============================================

  list(): string[] {
    return Array.from(this.connectors.keys())
  }

  size(): number {
    return this.connectors.size
  }

  clear(): void {
    this.connectors.clear()
  }
}

// ============================================
// Global Registry
// ============================================

export const registry = new ConnectorRegistry()