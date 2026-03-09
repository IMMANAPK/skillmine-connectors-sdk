// ============================================
// TENABLE.SC TYPES - Complyment Connectors SDK
// ============================================
// On-Premises Security Center
// ============================================

// ============================================
// Configuration
// ============================================

export interface TenableScConfig {
  baseUrl: string // Required - on-prem URL
  accessKey: string
  secretKey: string
  timeout?: number
  retries?: number
  cache?: {
    enabled: boolean
    ttl: number
  }
  dryRun?: boolean
}

// ============================================
// Asset Interfaces
// ============================================

export interface TenableScAsset {
  id: string
  name: string
  description?: string
  type?: string
  ipCount?: number
  vulns?: {
    critical?: number
    high?: number
    medium?: number
    low?: number
    info?: number
    total?: number
  }
  repositories?: TenableScRepository[]
  tags?: string[]
  owner?: {
    id: string
    username: string
  }
  ownerGroup?: {
    id: string
    name: string
  }
  status?: string
  createdTime?: string
  modifiedTime?: string
  [key: string]: unknown
}

export interface TenableScRepository {
  id: string
  name: string
  description?: string
}

export interface TenableScAssetsResponse {
  response: {
    usable: TenableScAsset[]
    manageable?: TenableScAsset[]
  }
  error_code?: number
  error_msg?: string
}

// ============================================
// Vulnerability Interfaces
// ============================================

export interface TenableScVulnerability {
  pluginID: string
  pluginName?: string
  severity?: {
    id: string
    name: string
    description?: string
  }
  ip?: string
  port?: string
  protocol?: string
  family?: {
    id: string
    name: string
  }
  repository?: {
    id: string
    name: string
  }
  firstSeen?: string
  lastSeen?: string
  exploitAvailable?: string
  patchAvailable?: string
  solution?: string
  synopsis?: string
  description?: string
  riskFactor?: string
  cvssV3BaseScore?: string
  cvssV2BaseScore?: string
  cve?: string
  cpe?: string
  vprScore?: string
  hasBeenMitigated?: string
  acceptRisk?: string
  recastRisk?: string
  hostUniqueness?: string
  hostUUID?: string
  assetExposureScore?: string
  netbiosName?: string
  dnsName?: string
  macAddress?: string
  operatingSystem?: string
  [key: string]: unknown
}

export interface TenableScAnalysisResponse {
  response: {
    totalRecords: string
    returnedRecords: number
    startOffset: string
    endOffset: string
    matchingDataElementCount: string
    results: TenableScVulnerability[]
  }
  error_code?: number
  error_msg?: string
}

// ============================================
// Policy Interfaces
// ============================================

export interface TenableScPolicy {
  id: string
  name: string
  description?: string
  context?: string
  status?: string
  policyTemplate?: {
    id: string
    name: string
  }
  creator?: {
    id: string
    username: string
  }
  owner?: {
    id: string
    username: string
  }
  ownerGroup?: {
    id: string
    name: string
  }
  tags?: string
  createdTime?: string
  modifiedTime?: string
  auditFiles?: unknown[]
  preferences?: Record<string, unknown>
  [key: string]: unknown
}

export interface TenableScPoliciesResponse {
  response: {
    usable: TenableScPolicy[]
    manageable?: TenableScPolicy[]
  }
  error_code?: number
  error_msg?: string
}

// ============================================
// User Interfaces
// ============================================

export interface TenableScUser {
  id: string
  username: string
  firstname?: string
  lastname?: string
  email?: string
  status?: string
  role?: {
    id: string
    name: string
    description?: string
  }
  group?: {
    id: string
    name: string
  }
  authType?: string
  locked?: string
  failedLogins?: string
  lastLogin?: string
  lastLoginIP?: string
  createdTime?: string
  modifiedTime?: string
  preferences?: Record<string, unknown>
  [key: string]: unknown
}

export interface TenableScUsersResponse {
  response: TenableScUser[]
  error_code?: number
  error_msg?: string
}

export interface CreateUserParams {
  username: string
  password?: string
  email?: string
  firstname?: string
  lastname?: string
  role: {
    id: number | string
  }
  group?: {
    id: number | string
  }
  authType?: string
  [key: string]: unknown
}

export interface UpdateUserParams {
  username?: string
  email?: string
  firstname?: string
  lastname?: string
  role?: {
    id: number | string
  }
  group?: {
    id: number | string
  }
  status?: string
  [key: string]: unknown
}

// ============================================
// Role Interfaces
// ============================================

export interface TenableScRole {
  id: string
  name: string
  description?: string
  createdTime?: string
  modifiedTime?: string
  permManageApp?: string
  permManageGroups?: string
  permManageRoles?: string
  permManageUsers?: string
  permManageBlackoutWindows?: string
  permManageScanPolicies?: string
  permManageAuditFiles?: string
  permManageCredentials?: string
  permManageRepositories?: string
  permManageAttributeSets?: string
  permManageAcceptRiskRules?: string
  permManageRecastRiskRules?: string
  permScan?: string
  permAgentScan?: string
  permShareObjects?: string
  [key: string]: unknown
}

export interface TenableScRolesResponse {
  response: TenableScRole[]
  error_code?: number
  error_msg?: string
}

// ============================================
// Scan Interfaces
// ============================================

export interface TenableScScan {
  id: string
  name: string
  description?: string
  status?: string
  type?: string
  policy?: {
    id: string
    name: string
  }
  repository?: {
    id: string
    name: string
  }
  zone?: {
    id: string
    name: string
  }
  schedule?: {
    type: string
    start?: string
    repeatRule?: string
  }
  owner?: {
    id: string
    username: string
  }
  createdTime?: string
  modifiedTime?: string
  [key: string]: unknown
}

export interface TenableScScansResponse {
  response: {
    usable: TenableScScan[]
    manageable?: TenableScScan[]
  }
  error_code?: number
  error_msg?: string
}

// ============================================
// Scan Result Interfaces
// ============================================

export interface TenableScScanResult {
  id: string
  name: string
  description?: string
  status?: string
  initiator?: {
    id: string
    username: string
  }
  owner?: {
    id: string
    username: string
  }
  repository?: {
    id: string
    name: string
  }
  scan?: {
    id: string
    name: string
  }
  importStatus?: string
  importStart?: string
  importFinish?: string
  startTime?: string
  finishTime?: string
  totalIPs?: string
  scannedIPs?: string
  completedIPs?: string
  completedChecks?: string
  totalChecks?: string
  [key: string]: unknown
}

export interface TenableScScanResultsResponse {
  response: {
    usable: TenableScScanResult[]
    manageable?: TenableScScanResult[]
  }
  error_code?: number
  error_msg?: string
}

// ============================================
// Repository Interfaces
// ============================================

export interface TenableScRepositoryResponse {
  response: TenableScRepository[]
  error_code?: number
  error_msg?: string
}

// ============================================
// Analysis Query Interfaces
// ============================================

export interface AnalysisFilter {
  filterName: string
  operator: '=' | '!=' | '>' | '<' | '>=' | '<=' | 'like' | 'regex'
  value: string | number
}

export interface AnalysisQuery {
  tool?: string
  filters?: AnalysisFilter[]
  startOffset?: number
  endOffset?: number
  sortField?: string
  sortDir?: 'ASC' | 'DESC'
}

// ============================================
// Statistics
// ============================================

export interface TenableScStats {
  summary: {
    totalAssets: number
    totalVulnerabilities: number
    criticalVulns: number
    highVulns: number
    totalPolicies: number
    totalUsers: number
  }
  latestAssets: TenableScAsset[]
  latestVulnerabilities: TenableScVulnerability[]
}

// ============================================
// Filter Types
// ============================================

export enum TenableScAnalysisType {
  VULN = 'vuln',
  EVENT = 'event',
  MOBILE = 'mobile',
  USER = 'user',
}

export enum TenableScSourceType {
  CUMULATIVE = 'cumulative',
  PATCHED = 'patched',
  INDIVIDUAL = 'individual',
  ARCHIVE = 'archive',
}

export enum TenableScSortDirection {
  ASC = 'ASC',
  DESC = 'DESC',
}

export interface GetAssetsFilter {
  fields?: string
  filter?: string
  sortField?: string
  sortDir?: TenableScSortDirection
}

export interface GetVulnerabilitiesFilter {
  type?: TenableScAnalysisType
  sourceType?: TenableScSourceType
  query?: AnalysisQuery
  startOffset?: number
  endOffset?: number
  severity?: string
}

export interface GetPoliciesFilter {
  fields?: string
  filter?: string
  sortField?: string
  sortDir?: TenableScSortDirection
}

export interface GetUsersFilter {
  fields?: string
  filter?: string
  sortField?: string
  sortDir?: TenableScSortDirection
}

export interface GetRolesFilter {
  fields?: string
  filter?: string
}

export interface TenableScGetScansFilter {
  fields?: string
  filter?: string
  sortField?: string
  sortDir?: TenableScSortDirection
}

export interface GetScanResultsFilter {
  fields?: string
  filter?: string
  sortField?: string
  sortDir?: TenableScSortDirection
  startOffset?: number
  endOffset?: number
}

export interface GetRepositoriesFilter {
  fields?: string
  filter?: string
}

// ============================================
// Generic API Response
// ============================================

export interface TenableScApiResponse<T> {
  response: T
  error_code?: number
  error_msg?: string
}
