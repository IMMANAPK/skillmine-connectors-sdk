// ============================================
// CHECKPOINT TYPES - Complyment Connectors SDK
// ============================================

// ============================================
// Config
// ============================================

export interface CheckpointConfig {
  baseUrl: string
  username: string
  password: string
  domain?: string
  timeout?: number
  retries?: number
  cache?: { enabled: boolean; ttl: number }
  dryRun?: boolean
}

// ============================================
// Session
// ============================================

export interface CheckpointSession {
  sid: string
  uid: string
  url: string
  sessionTimeout: number
  lastLoginWasAt: string
}

// ============================================
// Policy
// ============================================

export type CheckpointRuleAction =
  | 'Accept'
  | 'Drop'
  | 'Reject'
  | 'Ask'
  | 'Inform'

export interface CheckpointRule {
  uid: string
  name: string
  enabled: boolean
  action: CheckpointRuleAction
  source: string[]
  destination: string[]
  service: string[]
  track: string
  comments?: string
  installOn: string[]
}

export interface CheckpointPolicy {
  uid: string
  name: string
  type: string
  rules: CheckpointRule[]
  installedOn?: string[]
}

// ============================================
// Network Objects
// ============================================

export interface CheckpointHost {
  uid: string
  name: string
  ipAddress: string
  subnetMask?: string
  comments?: string
  groups?: string[]
}

export interface CheckpointNetwork {
  uid: string
  name: string
  subnet: string
  subnetMask: string
  comments?: string
}

export interface CheckpointGroup {
  uid: string
  name: string
  members: string[]
  comments?: string
}

// ============================================
// Threat Prevention
// ============================================

export type CheckpointThreatSeverity =
  | 'Critical'
  | 'High'
  | 'Medium'
  | 'Low'

export interface CheckpointThreat {
  uid: string
  name: string
  severity: CheckpointThreatSeverity
  confidence: 'High' | 'Medium' | 'Low'
  performanceImpact: 'High' | 'Medium' | 'Low'
  protectionType: string
  affectedSystems: string[]
  cve?: string[]
}

// ============================================
// Logs
// ============================================

export interface CheckpointLog {
  id: string
  time: string
  action: string
  origin: string
  sourceIp: string
  destinationIp: string
  service: string
  blade: string
  severity?: CheckpointThreatSeverity
  description?: string
}

export interface CheckpointLogFilter {
  startTime?: string
  endTime?: string
  action?: string
  sourceIp?: string
  destinationIp?: string
  severity?: CheckpointThreatSeverity[]
  limit?: number
}

// ============================================
// Gateway
// ============================================

export type CheckpointGatewayStatus =
  | 'OK'
  | 'Warning'
  | 'Error'
  | 'Disconnected'

export interface CheckpointGateway {
  uid: string
  name: string
  ipAddress: string
  osName: string
  version: string
  status: CheckpointGatewayStatus
  blades: string[]
  lastUpdateTime: string
}

// ============================================
// Filters
// ============================================

export interface CheckpointRuleFilter {
  policyName?: string
  enabled?: boolean
  action?: CheckpointRuleAction
  limit?: number
  offset?: number
}

export interface CheckpointHostFilter {
  name?: string
  ipAddress?: string
  limit?: number
  offset?: number
}