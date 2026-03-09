// ============================================
// TENABLE.IO TYPES - Complyment Connectors SDK
// ============================================
// Cloud-based Vulnerability Management Platform
// ============================================

// ============================================
// Configuration
// ============================================

export interface TenableIoConfig {
  baseUrl?: string // Default: https://cloud.tenable.com
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

export interface TenableIoAsset {
  id: string
  uuid?: string
  has_agent: boolean
  has_plugin_results?: boolean
  created_at?: string
  terminated_at?: string
  terminated_by?: string
  updated_at?: string
  deleted_at?: string
  deleted_by?: string
  first_seen?: string
  last_seen?: string
  first_scan_time?: string
  last_scan_time?: string
  last_authenticated_scan_date?: string
  last_licensed_scan_date?: string
  last_scan_id?: string
  last_schedule_id?: string
  azure_vm_id?: string
  azure_resource_id?: string
  aws_ec2_instance_ami_id?: string
  aws_ec2_instance_id?: string
  agent_uuid?: string
  bios_uuid?: string
  network_id?: string
  network_name?: string
  aws_owner_id?: string
  aws_availability_zone?: string
  aws_region?: string
  aws_vpc_id?: string
  aws_ec2_instance_group_name?: string
  aws_ec2_instance_state_name?: string
  aws_ec2_instance_type?: string
  aws_subnet_id?: string
  aws_ec2_product_code?: string
  aws_ec2_name?: string
  mcafee_epo_guid?: string
  mcafee_epo_agent_guid?: string
  servicenow_sysid?: string
  bigfix_asset_id?: string
  agent_names?: string[]
  installed_software?: string[]
  ipv4s?: string[]
  ipv6s?: string[]
  fqdns?: string[]
  mac_addresses?: string[]
  netbios_names?: string[]
  operating_systems?: string[]
  system_types?: string[]
  hostnames?: string[]
  ssh_fingerprints?: string[]
  qualys_asset_ids?: string[]
  qualys_host_ids?: string[]
  manufacturer_tpm_ids?: string[]
  symantec_ep_hardware_keys?: string[]
  sources?: TenableIoAssetSource[]
  tags?: TenableIoTag[]
  network_interfaces?: TenableIoNetworkInterface[]
  acr_score?: number
  exposure_score?: number
  [key: string]: unknown
}

export interface TenableIoAssetSource {
  name: string
  first_seen?: string
  last_seen?: string
}

export interface TenableIoTag {
  tag_uuid: string
  tag_key: string
  tag_value: string
  added_by?: string
  added_at?: string
}

export interface TenableIoNetworkInterface {
  name?: string
  virtual?: boolean
  aliased?: boolean
  fqdns?: string[]
  mac_addresses?: string[]
  ipv4s?: string[]
  ipv6s?: string[]
}

export interface TenableIoAssetsResponse {
  assets: TenableIoAsset[]
  total?: number
}

// ============================================
// Vulnerability Interfaces
// ============================================

export interface TenableIoVulnerability {
  asset?: {
    uuid?: string
    hostname?: string
    ipv4?: string
    operating_system?: string[]
    network_id?: string
    tracked?: boolean
  }
  output?: string
  plugin?: TenableIoPlugin
  port?: {
    port?: number
    protocol?: string
    service?: string
  }
  scan?: {
    completed_at?: string
    schedule_uuid?: string
    started_at?: string
    uuid?: string
  }
  severity?: string
  severity_id?: number
  severity_default_id?: number
  severity_modification_type?: string
  first_found?: string
  last_found?: string
  last_fixed?: string
  state?: string
  indexed?: string
  [key: string]: unknown
}

export interface TenableIoPlugin {
  bid?: number[]
  canvas_package?: string
  checks_for_default_account?: boolean
  checks_for_malware?: boolean
  cpe?: string[]
  cve?: string[]
  cvss3_base_score?: number
  cvss3_temporal_score?: number
  cvss3_temporal_vector?: string
  cvss3_vector?: string
  cvss_base_score?: number
  cvss_temporal_score?: number
  cvss_temporal_vector?: string
  cvss_vector?: string
  d2_elliot_name?: string
  description?: string
  exploit_available?: boolean
  exploit_framework_canvas?: boolean
  exploit_framework_core?: boolean
  exploit_framework_d2_elliot?: boolean
  exploit_framework_exploithub?: boolean
  exploit_framework_metasploit?: boolean
  exploitability_ease?: string
  exploited_by_malware?: boolean
  exploited_by_nessus?: boolean
  family?: string
  family_id?: number
  has_patch?: boolean
  id?: number
  in_the_news?: boolean
  metasploit_name?: string
  ms_bulletin?: string
  name?: string
  patch_publication_date?: string
  plugin_modification_date?: string
  plugin_publication_date?: string
  risk_factor?: string
  see_also?: string[]
  solution?: string
  stig_severity?: string
  synopsis?: string
  type?: string
  unsupported_by_vendor?: boolean
  version?: string
  vpr?: {
    score?: number
    drivers?: Record<string, unknown>
  }
  vuln_publication_date?: string
  xrefs?: string[]
}

// ============================================
// Export Job Interfaces
// ============================================

export interface TenableIoExportJob {
  uuid: string
  status?: string
  chunks_available?: number[]
  chunks_failed?: number[]
  chunks_cancelled?: number[]
  total_chunks?: number
  finished_chunks?: number
  created?: number
  filters?: Record<string, unknown>
  num_assets_per_chunk?: number
  empty_chunks_count?: number
}

export interface TenableIoExportStatusResponse {
  status: string
  chunks_available?: number[]
  chunks_failed?: number[]
  chunks_cancelled?: number[]
  total_chunks?: number
  finished_chunks?: number
}

// ============================================
// Scan Interfaces
// ============================================

export interface TenableIoScan {
  id: number
  uuid?: string
  name: string
  description?: string
  folder_id?: number
  type?: string
  read?: boolean
  last_modification_date?: number
  creation_date?: number
  status?: string
  shared?: boolean
  user_permissions?: number
  owner?: string
  timezone?: string
  rrules?: string
  starttime?: string
  enabled?: boolean
  control?: boolean
  live_results?: number
  template_uuid?: string
  policy_id?: number
  [key: string]: unknown
}

export interface TenableIoScansResponse {
  scans: TenableIoScan[]
  folders?: TenableIoFolder[]
  timestamp?: number
}

export interface TenableIoFolder {
  id: number
  name: string
  type: string
  default_tag?: number
  custom?: number
  unread_count?: number
}

export interface TenableIoLaunchScanResponse {
  scan_uuid: string
}

// ============================================
// User Interfaces
// ============================================

export interface TenableIoUser {
  uuid: string
  id: number
  user_name: string
  username: string
  email: string
  name?: string
  type?: string
  container_uuid?: string
  permissions?: number
  login_fail_count?: number
  login_fail_total?: number
  enabled?: boolean
  two_factor?: {
    email_enabled?: boolean
    sms_enabled?: boolean
    sms_phone?: string
  }
  last_login?: number
  last_login_attempt?: number
  uuid_id?: string
  [key: string]: unknown
}

export interface TenableIoUsersResponse {
  users: TenableIoUser[]
}

// ============================================
// Server Info Interfaces
// ============================================

export interface TenableIoServerInfo {
  nessus_type?: string
  nessus_ui_version?: string
  server_version?: string
  server_uuid?: string
  plugin_set?: string
  expiration?: number
  expiration_time?: number
  capabilities?: Record<string, unknown>
  license?: Record<string, unknown>
  update?: unknown
  enterprise?: boolean
  loaded_plugin_set?: string
  analytics?: Record<string, unknown>
  [key: string]: unknown
}

export interface TenableIoServerStatus {
  code: number
  status: string
}

// ============================================
// Agent Interfaces
// ============================================

export interface TenableIoAgent {
  id: number
  uuid: string
  name: string
  platform: string
  distro?: string
  ip?: string
  last_scanned?: number
  plugin_feed_id?: string
  core_build?: string
  core_version?: string
  linked_on?: number
  last_connect?: number
  status?: string
  groups?: TenableIoAgentGroup[]
  [key: string]: unknown
}

export interface TenableIoAgentGroup {
  id: number
  name: string
  uuid?: string
}

export interface TenableIoAgentsResponse {
  agents: TenableIoAgent[]
  pagination?: TenableIoPagination
}

// ============================================
// Scanner Interfaces
// ============================================

export interface TenableIoScanner {
  id: number
  uuid: string
  name: string
  type?: string
  status?: string
  scan_count?: number
  engine_version?: string
  platform?: string
  loaded_plugin_set?: string
  registration_code?: string
  owner?: string
  key?: string
  license?: Record<string, unknown>
  pool?: boolean
  linked?: number
  network_name?: string
  supports_remote_logs?: boolean
  supports_remote_settings?: boolean
  supports_webapp?: boolean
  [key: string]: unknown
}

export interface TenableIoScannersResponse {
  scanners: TenableIoScanner[]
}

// ============================================
// Pagination
// ============================================

export interface TenableIoPagination {
  total: number
  limit: number
  offset: number
  sort?: {
    name: string
    order: string
  }[]
}

// ============================================
// Workbench Interfaces
// ============================================

export interface WorkbenchVulnerability {
  count: number
  plugin_family: string
  plugin_id: number
  plugin_name: string
  vulnerability_state: string
  accepted_count: number
  recasted_count: number
  counts_by_severity: WorkbenchSeverityCount[]
  severity: number
  vpr_score?: number
  [key: string]: unknown
}

export interface WorkbenchSeverityCount {
  count: number
  value: number
}

export interface WorkbenchVulnerabilitiesResponse {
  vulnerabilities: WorkbenchVulnerability[]
  total_vulnerability_count?: number
  total_asset_count?: number
}

export interface WorkbenchAsset {
  id: string
  has_agent: boolean
  has_plugin_results: boolean
  created_at: string
  terminated_at?: string
  terminated_by?: string
  updated_at: string
  deleted_at?: string
  deleted_by?: string
  first_seen: string
  last_seen: string
  first_scan_time?: string
  last_scan_time?: string
  last_authenticated_scan_date?: string
  last_licensed_scan_date?: string
  last_scan_id?: string
  last_schedule_id?: string
  sources: WorkbenchAssetSource[]
  tags?: TenableIoTag[]
  acr_score?: number
  acr_drivers?: Record<string, unknown>
  exposure_score?: number
  scan_frequency?: Record<string, unknown>
  ipv4?: string[]
  ipv6?: string[]
  fqdn?: string[]
  netbios_name?: string[]
  operating_system?: string[]
  agent_name?: string[]
  aws_ec2_name?: string[]
  mac_address?: string[]
  severities?: WorkbenchAssetSeverity[]
  total?: number
  [key: string]: unknown
}

export interface WorkbenchAssetSource {
  name: string
  first_seen: string
  last_seen: string
}

export interface WorkbenchAssetSeverity {
  count: number
  level: number
  name: string
}

export interface WorkbenchAssetsResponse {
  assets: WorkbenchAsset[]
  total: number
}

export interface WorkbenchVulnInfo {
  count: number
  description: string
  discovery: {
    seen_first: string
    seen_last: string
  }
  plugin_details: {
    family: string
    modification_date: string
    name: string
    publication_date: string
    severity: number
    type: string
    version: string
  }
  reference_information?: {
    cve?: string[]
    cpe?: string[]
    bid?: string[]
    xref?: string[]
    see_also?: string[]
  }
  risk_information?: {
    cvss3_base_score?: string
    cvss3_temporal_score?: string
    cvss3_vector?: string
    cvss_base_score?: string
    cvss_temporal_score?: string
    cvss_vector?: string
    risk_factor?: string
    stig_severity?: string
  }
  severity: number
  solution?: string
  synopsis?: string
  vpr?: {
    score?: number
    drivers?: Record<string, unknown>
  }
  vuln_count: number
  [key: string]: unknown
}

export interface WorkbenchVulnInfoResponse {
  info: WorkbenchVulnInfo
}

export interface WorkbenchAssetInfo {
  counts: {
    vulnerabilities: {
      total: number
      severities: WorkbenchAssetSeverity[]
    }
    audits?: {
      total: number
      statuses: Record<string, unknown>[]
    }
  }
  id: string
  has_agent: boolean
  created_at: string
  updated_at: string
  first_seen: string
  last_seen: string
  last_scan_time?: string
  sources: WorkbenchAssetSource[]
  tags?: TenableIoTag[]
  acr_score?: number
  exposure_score?: number
  fqdns?: string[]
  hostnames?: string[]
  ipv4s?: string[]
  ipv6s?: string[]
  mac_addresses?: string[]
  netbios_names?: string[]
  operating_systems?: string[]
  [key: string]: unknown
}

export interface WorkbenchAssetInfoResponse {
  info: WorkbenchAssetInfo
}

export interface WorkbenchAssetVulnsResponse {
  vulnerabilities: WorkbenchVulnerability[]
}

// ============================================
// Statistics
// ============================================

export interface TenableIoStats {
  summary: {
    totalAssets: number
    totalVulnerabilities: number
    criticalVulns: number
    highVulns: number
    mediumVulns: number
    lowVulns: number
    totalScans: number
    totalUsers: number
    totalAgents: number
  }
  recentAssets: TenableIoAsset[]
  recentScans: TenableIoScan[]
}

// ============================================
// Filter Types
// ============================================

export enum TenableIoSeverity {
  INFO = 'info',
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

export enum TenableIoVulnState {
  OPEN = 'open',
  REOPENED = 'reopened',
  FIXED = 'fixed',
}

export interface ExportAssetsFilter {
  chunk_size?: number
  created_at?: number
  updated_at?: number
  terminated_at?: number
  deleted_at?: number
  first_scan_time?: number
  last_authenticated_scan_time?: number
  last_assessed?: number
  servicenow_sysid?: boolean
  sources?: string[]
  has_plugin_results?: boolean
  tag_category?: string
  tag_value?: string
}

export interface ExportVulnerabilitiesFilter {
  num_assets?: number
  severity?: TenableIoSeverity[]
  state?: TenableIoVulnState[]
  plugin_family?: string[]
  since?: number
  cidr_range?: string
  first_found?: number
  last_found?: number
  last_fixed?: number
}

export interface TenableIoGetScansFilter {
  folder_id?: number
  last_modification_date?: number
}

export interface GetAgentsFilter {
  limit?: number
  offset?: number
  sort?: string
  filter?: string
}

export interface GetWorkbenchVulnsFilter {
  age?: number
  filter_search_type?: string
  exploitable?: boolean
  date_range?: number
  severity?: string[]
}

export interface GetWorkbenchAssetsFilter {
  date_range?: number
  filter_search_type?: string
  has_agent?: boolean
}
