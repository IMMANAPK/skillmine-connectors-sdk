// ============================================
// QUALYS TYPES - Complyment Connectors SDK
// ============================================

// ============================================
// Auth
// ============================================

export interface QualysConfig {
  baseUrl: string
  username: string
  password: string
  timeout?: number
  retries?: number
  cache?: { enabled: boolean; ttl: number }
  dryRun?: boolean
}

// ============================================
// Asset Management
// ============================================

export interface QualysAsset {
  id: string
  hostname: string
  ipAddress: string
  os?: string
  osVersion?: string
  type: string
  lastSeen: string
  tags?: string[]
  netbiosName?: string
  dnsName?: string
  agentId?: string
}

export interface QualysAssetListResponse {
  assets: QualysAsset[]
  total: number
  page: number
  limit: number
}

// ============================================
// Vulnerability Management
// ============================================

export type QualysSeverity = 1 | 2 | 3 | 4 | 5

export interface QualysVulnerability {
  qid: string
  title: string
  severity: QualysSeverity
  cvssBase?: number
  cvssV3?: number
  cve?: string[]
  affectedHostname: string
  affectedIp: string
  firstDetected: string
  lastDetected: string
  status: 'Active' | 'Fixed' | 'New' | 'Re-Opened'
  category?: string
  solution?: string
  description?: string
}

export interface QualysVulnListResponse {
  vulnerabilities: QualysVulnerability[]
  total: number
  page: number
  limit: number
}

// ============================================
// Scan Management
// ============================================

export type QualysScanStatus =
  | 'Running'
  | 'Finished'
  | 'Paused'
  | 'Cancelled'
  | 'Error'

export interface QualysScan {
  id: string
  title: string
  status: QualysScanStatus
  type: 'Vulnerability' | 'Compliance' | 'Web Application'
  launchedAt: string
  completedAt?: string
  targetHosts?: string[]
  duration?: number
}

export interface QualysScanListResponse {
  scans: QualysScan[]
  total: number
}

// ============================================
// Report
// ============================================

export interface QualysReport {
  id: string
  title: string
  type: string
  status: 'Finished' | 'Running' | 'Submitted' | 'Cancelled'
  createdAt: string
  size?: number
  format: 'PDF' | 'HTML' | 'XML' | 'CSV' | 'DOCX'
}

// ============================================
// Compliance
// ============================================

export interface QualysComplianceControl {
  id: string
  title: string
  status: 'Pass' | 'Fail' | 'Error' | 'Exception'
  severity: QualysSeverity
  standard: string
  section: string
  lastChecked: string
}

// ============================================
// Filter Options
// ============================================

export interface QualysVulnFilter {
  severity?: QualysSeverity[]
  status?: ('Active' | 'Fixed' | 'New' | 'Re-Opened')[]
  hostname?: string
  ipAddress?: string
  cve?: string
  page?: number
  limit?: number
}

export interface QualysAssetFilter {
  hostname?: string
  ipAddress?: string
  os?: string
  tags?: string[]
  page?: number
  limit?: number
}

export interface QualysScanFilter {
  status?: QualysScanStatus[]
  type?: string
  page?: number
  limit?: number
}