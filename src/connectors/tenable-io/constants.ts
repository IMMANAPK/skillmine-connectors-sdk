// ============================================
// TENABLE.IO CONSTANTS - Complyment Connectors SDK
// ============================================

// ============================================
// API Endpoints
// ============================================

export const TENABLE_IO_API_PATHS = {
  // Server
  SERVER_PROPERTIES: '/server/properties',
  SERVER_STATUS: '/server/status',

  // Assets
  ASSETS: '/assets',
  ASSET_BY_ID: (uuid: string) => `/assets/${uuid}`,
  ASSETS_EXPORT: '/assets/export',
  ASSETS_EXPORT_STATUS: (uuid: string) => `/assets/export/${uuid}/status`,
  ASSETS_EXPORT_CHUNK: (uuid: string, chunkId: number) => `/assets/export/${uuid}/chunks/${chunkId}`,

  // Vulnerabilities
  VULNS_EXPORT: '/vulns/export',
  VULNS_EXPORT_STATUS: (uuid: string) => `/vulns/export/${uuid}/status`,
  VULNS_EXPORT_CHUNK: (uuid: string, chunkId: number) => `/vulns/export/${uuid}/chunks/${chunkId}`,
  VULNS_EXPORT_CANCEL: (uuid: string) => `/vulns/export/${uuid}/cancel`,

  // Scans
  SCANS: '/scans',
  SCAN_BY_ID: (scanId: string) => `/scans/${scanId}`,
  SCAN_LAUNCH: (scanId: string) => `/scans/${scanId}/launch`,
  SCAN_PAUSE: (scanId: string) => `/scans/${scanId}/pause`,
  SCAN_RESUME: (scanId: string) => `/scans/${scanId}/resume`,
  SCAN_STOP: (scanId: string) => `/scans/${scanId}/stop`,

  // Users
  USERS: '/users',
  USER_BY_ID: (userId: string) => `/users/${userId}`,

  // Agents
  AGENTS: '/scanners/1/agents',

  // Scanners
  SCANNERS: '/scanners',
  SCANNER_BY_ID: (scannerId: string) => `/scanners/${scannerId}`,

  // Workbench
  WORKBENCH_VULNERABILITIES: '/workbenches/vulnerabilities',
  WORKBENCH_VULN_INFO: (pluginId: number) => `/workbenches/vulnerabilities/${pluginId}/info`,
  WORKBENCH_ASSETS: '/workbenches/assets',
  WORKBENCH_ASSET_INFO: (assetUuid: string) => `/workbenches/assets/${assetUuid}/info`,
  WORKBENCH_ASSET_VULNS: (assetUuid: string) => `/workbenches/assets/${assetUuid}/vulnerabilities`,
} as const

// ============================================
// Default Configuration
// ============================================

export const TENABLE_IO_DEFAULTS = {
  BASE_URL: 'https://cloud.tenable.com',
  TIMEOUT_MS: 60000,
  MAX_RETRIES: 3,
  RATE_LIMIT_REQUESTS: 40,
  RATE_LIMIT_WINDOW_SECONDS: 1,
  EXPORT_CHUNK_SIZE: 1000,
  EXPORT_POLL_INTERVAL_MS: 5000,
  EXPORT_MAX_WAIT_MS: 3600000, // 1 hour
} as const

// ============================================
// Headers
// ============================================

export const TENABLE_IO_HEADERS = {
  CONTENT_TYPE: 'application/json',
  ACCEPT: 'application/json',
} as const

// ============================================
// Severity Mapping
// ============================================

export const TENABLE_IO_SEVERITY_MAP: Record<number, string> = {
  0: 'info',
  1: 'low',
  2: 'medium',
  3: 'high',
  4: 'critical',
} as const

export const TENABLE_IO_SEVERITY_ID_MAP: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
} as const

// ============================================
// Export Status
// ============================================

export enum TenableIoExportStatus {
  QUEUED = 'QUEUED',
  PROCESSING = 'PROCESSING',
  FINISHED = 'FINISHED',
  ERROR = 'ERROR',
  CANCELLED = 'CANCELLED',
}

export const isExportComplete = (status: string): boolean =>
  status === TenableIoExportStatus.FINISHED ||
  status === TenableIoExportStatus.ERROR ||
  status === TenableIoExportStatus.CANCELLED

export const isExportSuccess = (status: string): boolean =>
  status === TenableIoExportStatus.FINISHED
