// ============================================
// MANAGEENGINE TYPES - Skillmine Connectors SDK
// ============================================

// ============================================
// Config
// ============================================

export interface ManageEngineConfig {
  baseUrl: string
  clientId: string
  clientSecret: string
  refreshToken: string
  timeout?: number
  retries?: number
  cache?: { enabled: boolean; ttl: number }
  dryRun?: boolean
}

// ============================================
// Patch Management
// ============================================

export type PatchStatus =
  | 'Missing'
  | 'Installed'
  | 'Failed'
  | 'NotApplicable'
  | 'Pending'

export type PatchSeverity =
  | 'Critical'
  | 'Important'
  | 'Moderate'
  | 'Low'
  | 'Unrated'

export interface ManageEnginePatch {
  patchId: string
  title: string
  severity: PatchSeverity
  status: PatchStatus
  kb?: string
  cve?: string[]
  releaseDate: string
  installDate?: string
  affectedComputers: number
  bulletinId?: string
  description?: string
  rebootRequired: boolean
}

export interface ManageEnginePatchListResponse {
  patches: ManageEnginePatch[]
  total: number
  page: number
  limit: number
}

// ============================================
// Computer / Asset
// ============================================

export type ComputerStatus = 'Live' | 'Down' | 'Unknown'

export interface ManageEngineComputer {
  computerId: string
  computerName: string
  ipAddress: string
  os: string
  osVersion: string
  domain?: string
  status: ComputerStatus
  lastContact: string
  agentVersion?: string
  missingPatchCount: number
  installedPatchCount: number
  pendingPatchCount: number
  groups?: string[]
}

export interface ManageEngineComputerListResponse {
  computers: ManageEngineComputer[]
  total: number
  page: number
  limit: number
}

// ============================================
// Deployment
// ============================================

export type DeploymentStatus =
  | 'Success'
  | 'Failed'
  | 'InProgress'
  | 'Pending'
  | 'Cancelled'

export interface ManageEngineDeployment {
  deploymentId: string
  name: string
  status: DeploymentStatus
  patchIds: string[]
  targetComputers: string[]
  scheduledAt: string
  completedAt?: string
  successCount: number
  failureCount: number
  pendingCount: number
}

// ============================================
// Vulnerability
// ============================================

export interface ManageEngineVulnerability {
  vulnerabilityId: string
  title: string
  severity: PatchSeverity
  cve: string[]
  affectedComputerId: string
  affectedComputerName: string
  patchAvailable: boolean
  patchId?: string
  detectedAt: string
}

// ============================================
// Filters
// ============================================

export interface ManageEnginePatchFilter {
  severity?: PatchSeverity[]
  status?: PatchStatus[]
  rebootRequired?: boolean
  page?: number
  limit?: number
}

export interface ManageEngineComputerFilter {
  status?: ComputerStatus[]
  domain?: string
  os?: string
  computerName?: string
  page?: number
  limit?: number
}

export interface ManageEngineDeploymentFilter {
  status?: DeploymentStatus[]
  page?: number
  limit?: number
}