// ============================================
// TENABLE.SC CONSTANTS - Complyment Connectors SDK
// ============================================

// ============================================
// API Endpoints
// ============================================

export const TENABLE_SC_API_PATHS = {
  // System
  SYSTEM: '/rest/system',

  // Assets
  ASSETS: '/rest/asset',
  ASSET_BY_ID: (assetId: string) => `/rest/asset/${assetId}`,

  // Analysis (Vulnerabilities)
  ANALYSIS: '/rest/analysis',

  // Policies
  POLICIES: '/rest/policy',
  POLICY_BY_ID: (policyId: string) => `/rest/policy/${policyId}`,

  // Users
  USERS: '/rest/user',
  USER_BY_ID: (userId: string) => `/rest/user/${userId}`,

  // Roles
  ROLES: '/rest/role',
  ROLE_BY_ID: (roleId: string) => `/rest/role/${roleId}`,

  // Scans
  SCANS: '/rest/scan',
  SCAN_BY_ID: (scanId: string) => `/rest/scan/${scanId}`,

  // Scan Results
  SCAN_RESULTS: '/rest/scanResult',
  SCAN_RESULT_BY_ID: (resultId: string) => `/rest/scanResult/${resultId}`,

  // Repositories
  REPOSITORIES: '/rest/repository',
  REPOSITORY_BY_ID: (repoId: string) => `/rest/repository/${repoId}`,
} as const

// ============================================
// Default Configuration
// ============================================

export const TENABLE_SC_DEFAULTS = {
  TIMEOUT_MS: 60000,
  MAX_RETRIES: 3,
  START_OFFSET: 0,
  END_OFFSET: 1000,
  DEFAULT_FIELDS: 'id,name,description',
} as const

// ============================================
// Headers
// ============================================

export const TENABLE_SC_HEADERS = {
  CONTENT_TYPE: 'application/json',
  ACCEPT: 'application/json',
} as const

// ============================================
// Severity Mapping
// ============================================

export const TENABLE_SC_SEVERITY_MAP: Record<string, string> = {
  '0': 'info',
  '1': 'low',
  '2': 'medium',
  '3': 'high',
  '4': 'critical',
} as const

export const TENABLE_SC_SEVERITY_ID_MAP: Record<string, string> = {
  info: '0',
  low: '1',
  medium: '2',
  high: '3',
  critical: '4',
} as const

// ============================================
// Analysis Tools
// ============================================

export const TENABLE_SC_ANALYSIS_TOOLS = {
  VULN_DETAILS: 'vulndetails',
  LIST_VULN: 'listvuln',
  SUM_IP: 'sumip',
  SUM_ASSET: 'sumasset',
  SUM_PORT: 'sumport',
  SUM_SEVERITY: 'sumseverity',
  SUM_PLUGIN: 'sumplugin',
  SUM_FAMILY: 'sumfamily',
  SUM_REPO: 'sumrepo',
  SUM_DNS_NAME: 'sumdnsname',
  SUM_NET_BIOS: 'sumnetbios',
  LIST_MAIL_CLIENTS: 'listmailclients',
  LIST_SERVICES: 'listservices',
  LIST_OS: 'listos',
  LIST_SOFTWARE: 'listsoftware',
  LIST_SSH_SERVERS: 'listsshservers',
  LIST_WEB_BROWSERS: 'listwebbrowsers',
  LIST_WEB_CLIENTS: 'listwebclients',
  LIST_WEB_SERVERS: 'listwebservers',
} as const
