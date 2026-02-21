// ============================================
// NORMALIZATION ENGINE - Skillmine Connectors SDK
// ============================================

import {
  NormalizedVulnerability,
  NormalizedAsset,
  NormalizedThreat,
} from '../core/types'

// ============================================
// Normalization Result
// ============================================

export interface NormalizationResult<T> {
  data: T[]
  total: number
  sources: string[]
  normalizedAt: Date
  errors: NormalizationError[]
}

export interface NormalizationError {
  source: string
  message: string
  raw?: unknown
}

// ============================================
// Severity Mapping
// ============================================

export type UnifiedSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export interface SeverityMapping {
  [key: string]: UnifiedSeverity
}

// ============================================
// Normalization Engine
// ============================================

export class NormalizationEngine {

  // ============================================
  // Vulnerability Normalization
  // ============================================

  normalizeVulnerabilities(
    sources: Array<{
      connector: string
      data: unknown[]
      mapper: (item: unknown) => NormalizedVulnerability | null
    }>,
  ): NormalizationResult<NormalizedVulnerability> {
    const normalized: NormalizedVulnerability[] = []
    const errors: NormalizationError[] = []
    const sourceNames: string[] = []

    for (const source of sources) {
      sourceNames.push(source.connector)

      for (const item of source.data) {
        try {
          const result = source.mapper(item)
          if (result) normalized.push(result)
        } catch (error) {
          errors.push({
            source: source.connector,
            message: error instanceof Error ? error.message : 'Mapping failed',
            raw: item,
          })
        }
      }
    }

    return {
      data: this.deduplicateVulnerabilities(normalized),
      total: normalized.length,
      sources: sourceNames,
      normalizedAt: new Date(),
      errors,
    }
  }

  // ============================================
  // Asset Normalization
  // ============================================

  normalizeAssets(
    sources: Array<{
      connector: string
      data: unknown[]
      mapper: (item: unknown) => NormalizedAsset | null
    }>,
  ): NormalizationResult<NormalizedAsset> {
    const normalized: NormalizedAsset[] = []
    const errors: NormalizationError[] = []
    const sourceNames: string[] = []

    for (const source of sources) {
      sourceNames.push(source.connector)

      for (const item of source.data) {
        try {
          const result = source.mapper(item)
          if (result) normalized.push(result)
        } catch (error) {
          errors.push({
            source: source.connector,
            message: error instanceof Error ? error.message : 'Mapping failed',
            raw: item,
          })
        }
      }
    }

    return {
      data: this.deduplicateAssets(normalized),
      total: normalized.length,
      sources: sourceNames,
      normalizedAt: new Date(),
      errors,
    }
  }

  // ============================================
  // Threat Normalization
  // ============================================

  normalizeThreats(
    sources: Array<{
      connector: string
      data: unknown[]
      mapper: (item: unknown) => NormalizedThreat | null
    }>,
  ): NormalizationResult<NormalizedThreat> {
    const normalized: NormalizedThreat[] = []
    const errors: NormalizationError[] = []
    const sourceNames: string[] = []

    for (const source of sources) {
      sourceNames.push(source.connector)

      for (const item of source.data) {
        try {
          const result = source.mapper(item)
          if (result) normalized.push(result)
        } catch (error) {
          errors.push({
            source: source.connector,
            message: error instanceof Error ? error.message : 'Mapping failed',
            raw: item,
          })
        }
      }
    }

    return {
      data: normalized,
      total: normalized.length,
      sources: sourceNames,
      normalizedAt: new Date(),
      errors,
    }
  }

  // ============================================
  // Deduplication
  // ============================================

  private deduplicateVulnerabilities(
    vulns: NormalizedVulnerability[],
  ): NormalizedVulnerability[] {
    const seen = new Map<string, NormalizedVulnerability>()

    for (const vuln of vulns) {
      // Deduplicate by CVE if available
      const key = vuln.cve ?? `${vuln.title}-${vuln.affectedAsset}`

      if (!seen.has(key)) {
        seen.set(key, vuln)
      } else {
        // Keep highest severity
        const existing = seen.get(key)!
        if (this.severityScore(vuln.severity) > this.severityScore(existing.severity)) {
          seen.set(key, vuln)
        }
      }
    }

    return Array.from(seen.values())
  }

  private deduplicateAssets(
    assets: NormalizedAsset[],
  ): NormalizedAsset[] {
    const seen = new Map<string, NormalizedAsset>()

    for (const asset of assets) {
      // Deduplicate by IP address
      const key = asset.ipAddress

      if (!seen.has(key)) {
        seen.set(key, asset)
      } else {
        // Keep most recently seen
        const existing = seen.get(key)!
        if (asset.lastSeen > existing.lastSeen) {
          seen.set(key, asset)
        }
      }
    }

    return Array.from(seen.values())
  }

  // ============================================
  // Severity Helpers
  // ============================================

  private severityScore(severity: UnifiedSeverity): number {
    const scores = {
      critical: 5,
      high: 4,
      medium: 3,
      low: 2,
      info: 1,
    }
    return scores[severity] ?? 0
  }

  mapSeverity(
    value: string,
    mapping: SeverityMapping,
  ): UnifiedSeverity {
    return mapping[value] ?? 'info'
  }

  // ============================================
  // Sort Helpers
  // ============================================

  sortBySeverity<T extends { severity: UnifiedSeverity }>(
    items: T[],
    order: 'asc' | 'desc' = 'desc',
  ): T[] {
    return [...items].sort((a, b) => {
      const diff = this.severityScore(b.severity) - this.severityScore(a.severity)
      return order === 'desc' ? diff : -diff
    })
  }

  // ============================================
  // Filter Helpers
  // ============================================

  filterBySeverity<T extends { severity: UnifiedSeverity }>(
    items: T[],
    minSeverity: UnifiedSeverity,
  ): T[] {
    const minScore = this.severityScore(minSeverity)
    return items.filter((item) => this.severityScore(item.severity) >= minScore)
  }

  // ============================================
  // Stats
  // ============================================

  getSeverityStats<T extends { severity: UnifiedSeverity }>(
    items: T[],
  ): Record<UnifiedSeverity, number> {
    return {
      critical: items.filter((i) => i.severity === 'critical').length,
      high: items.filter((i) => i.severity === 'high').length,
      medium: items.filter((i) => i.severity === 'medium').length,
      low: items.filter((i) => i.severity === 'low').length,
      info: items.filter((i) => i.severity === 'info').length,
    }
  }
}

// ============================================
// Global Instance
// ============================================

export const normalizationEngine = new NormalizationEngine()