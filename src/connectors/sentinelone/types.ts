// ============================================
// SENTINELONE TYPES - Complyment Connectors SDK
// ============================================

// ============================================
// Config
// ============================================

export interface SentinelOneConfig {
  baseUrl: string
  apiToken: string
  timeout?: number
  retries?: number
  cache?: { enabled: boolean; ttl: number }
  dryRun?: boolean
}

// ============================================
// Agent (Endpoint)
// ============================================

export type SentinelOneAgentStatus =
  | 'connected'
  | 'disconnected'
  | 'degraded'

export interface SentinelOneAgent {
  id: string
  computerName: string
  ipAddress: string
  osName: string
  osVersion: string
  status: SentinelOneAgentStatus
  infected: boolean
  isActive: boolean
  lastActiveDate: string
  agentVersion: string
  domain?: string
  siteName?: string
  groupName?: string
  tags?: string[]
  networkStatus: 'connected' | 'disconnected' | 'connecting'
  threatCount: number
  mitigationMode: 'protect' | 'detect' | 'none'
}

export interface SentinelOneAgentListResponse {
  data: SentinelOneAgent[]
  pagination: {
    totalItems: number
    nextCursor?: string
  }
}

// ============================================
// Threats
// ============================================

export type SentinelOneThreatStatus =
  | 'active'
  | 'mitigated'
  | 'resolved'
  | 'suspicious'
  | 'blocked'

export type SentinelOneConfidenceLevel =
  | 'malicious'
  | 'suspicious'
  | 'n/a'

export interface SentinelOneThreat {
  id: string
  threatName: string
  classification: string
  confidenceLevel: SentinelOneConfidenceLevel
  mitigationStatus: SentinelOneThreatStatus
  agentComputerName: string
  agentId: string
  filePath?: string
  fileHash?: string
  createdAt: string
  updatedAt: string
  siteName?: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  engines: string[]
  indicators?: string[]
}

export interface SentinelOneThreatListResponse {
  data: SentinelOneThreat[]
  pagination: {
    totalItems: number
    nextCursor?: string
  }
}

// ============================================
// Activities
// ============================================

export interface SentinelOneActivity {
  id: string
  activityType: number
  agentId?: string
  agentUpdatedVersion?: string
  createdAt: string
  data: Record<string, unknown>
  siteId?: string
  threatId?: string
  userId?: string
  primaryDescription: string
  secondaryDescription?: string
}

// ============================================
// Groups & Sites
// ============================================

export interface SentinelOneGroup {
  id: string
  name: string
  type: 'static' | 'dynamic'
  agentCount: number
  siteId: string
  rank?: number
}

export interface SentinelOneSite {
  id: string
  name: string
  state: 'active' | 'expired' | 'deleted'
  agentCount: number
  activeLicenses: number
  totalLicenses: number
  createdAt: string
}

// ============================================
// Filters
// ============================================

export interface SentinelOneAgentFilter {
  status?: SentinelOneAgentStatus[]
  infected?: boolean
  osName?: string
  groupName?: string
  siteName?: string
  computerName?: string
  limit?: number
  cursor?: string
}

export interface SentinelOneThreatFilter {
  status?: SentinelOneThreatStatus[]
  severity?: ('critical' | 'high' | 'medium' | 'low')[]
  confidenceLevel?: SentinelOneConfidenceLevel[]
  agentId?: string
  limit?: number
  cursor?: string
  createdAfter?: string
  createdBefore?: string
}

// ============================================
// Mitigation Actions
// ============================================

export type MitigationAction =
  | 'kill'
  | 'quarantine'
  | 'remediate'
  | 'rollback-remediation'
  | 'un-quarantine'

export interface MitigationRequest {
  threatIds: string[]
  action: MitigationAction
}

export interface MitigationResponse {
  affected: number
  success: boolean
}