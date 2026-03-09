// ============================================
// TENABLE.SC CONNECTOR - Complyment Connectors SDK
// ============================================
// On-Premises Security Center Connector
// Supports Assets, Vulnerabilities, Policies, Users, Roles, Scans
// ============================================

import { BaseConnector } from '../../core/BaseConnector'
import {
  ConnectorConfig,
  ConnectorResponse,
  AuthType,
  LogLevel,
} from '../../core/types'
import {
  TenableScConfig,
  TenableScAsset,
  TenableScAssetsResponse,
  TenableScVulnerability,
  TenableScAnalysisResponse,
  TenableScPolicy,
  TenableScPoliciesResponse,
  TenableScUser,
  TenableScUsersResponse,
  TenableScRole,
  TenableScRolesResponse,
  TenableScScan,
  TenableScScansResponse,
  TenableScScanResult,
  TenableScScanResultsResponse,
  TenableScRepository,
  TenableScRepositoryResponse,
  TenableScStats,
  TenableScAnalysisType,
  TenableScSourceType,
  GetAssetsFilter,
  GetVulnerabilitiesFilter,
  GetPoliciesFilter,
  GetUsersFilter,
  GetRolesFilter,
  TenableScGetScansFilter,
  GetScanResultsFilter,
  GetRepositoriesFilter,
  CreateUserParams,
  UpdateUserParams,
} from './types'
import {
  TENABLE_SC_API_PATHS,
  TENABLE_SC_DEFAULTS,
  TENABLE_SC_SEVERITY_MAP,
  TENABLE_SC_ANALYSIS_TOOLS,
} from './constants'

export class TenableScConnector extends BaseConnector {
  private tenableConfig: TenableScConfig

  constructor(tenableConfig: TenableScConfig) {
    const config: ConnectorConfig = {
      name: 'tenable-sc',
      baseUrl: tenableConfig.baseUrl,
      auth: {
        type: AuthType.API_KEY,
        apiKey: `accesskey=${tenableConfig.accessKey}; secretkey=${tenableConfig.secretKey};`,
        headerName: 'x-apikey',
      },
      timeout: tenableConfig.timeout ?? TENABLE_SC_DEFAULTS.TIMEOUT_MS,
      retries: tenableConfig.retries ?? TENABLE_SC_DEFAULTS.MAX_RETRIES,
      cache: tenableConfig.cache,
      dryRun: tenableConfig.dryRun,
      logger: LogLevel.INFO,
    }
    super(config)
    this.tenableConfig = tenableConfig
  }

  // ============================================
  // Auth (API Key handled by BaseConnector)
  // ============================================

  async authenticate(): Promise<void> {
    // API Key auth is injected automatically by BaseConnector
  }

  async testConnection(): Promise<boolean> {
    try {
      const response = await this.get<unknown>(TENABLE_SC_API_PATHS.SYSTEM)
      return response.success
    } catch {
      return false
    }
  }

  // ============================================
  // Asset Operations
  // ============================================

  /**
   * Get assets
   */
  async getAssets(filters: GetAssetsFilter = {}): Promise<ConnectorResponse<TenableScAssetsResponse>> {
    const params: Record<string, unknown> = {}
    if (filters.fields) params.fields = filters.fields
    if (filters.filter) params.filter = filters.filter
    if (filters.sortField) params.sortField = filters.sortField
    if (filters.sortDir) params.sortDir = filters.sortDir

    return this.get<TenableScAssetsResponse>(TENABLE_SC_API_PATHS.ASSETS, params)
  }

  /**
   * Get asset by ID
   */
  async getAssetById(assetId: string): Promise<ConnectorResponse<TenableScAsset>> {
    const response = await this.get<{ response: TenableScAsset }>(TENABLE_SC_API_PATHS.ASSET_BY_ID(assetId))
    return {
      ...response,
      data: response.data?.response,
    }
  }

  // ============================================
  // Vulnerability Operations
  // ============================================

  /**
   * Get vulnerabilities (Analysis API)
   */
  async getVulnerabilities(filters: GetVulnerabilitiesFilter = {}): Promise<ConnectorResponse<TenableScAnalysisResponse>> {
    const requestBody: Record<string, unknown> = {
      type: filters.type || TenableScAnalysisType.VULN,
      sourceType: filters.sourceType || TenableScSourceType.CUMULATIVE,
      query: filters.query || {
        tool: TENABLE_SC_ANALYSIS_TOOLS.VULN_DETAILS,
        startOffset: filters.startOffset || TENABLE_SC_DEFAULTS.START_OFFSET,
        endOffset: filters.endOffset || TENABLE_SC_DEFAULTS.END_OFFSET,
      },
    }

    // Add severity filter if provided
    if (filters.severity) {
      const query = requestBody.query as Record<string, unknown>
      if (!query.filters) {
        query.filters = []
      }
      (query.filters as unknown[]).push({
        filterName: 'severity',
        operator: '=',
        value: filters.severity,
      })
    }

    return this.post<TenableScAnalysisResponse>(TENABLE_SC_API_PATHS.ANALYSIS, requestBody)
  }

  /**
   * Get critical and high vulnerabilities
   */
  async getCriticalVulnerabilities(): Promise<ConnectorResponse<TenableScAnalysisResponse>> {
    return this.getVulnerabilities({
      type: TenableScAnalysisType.VULN,
      sourceType: TenableScSourceType.CUMULATIVE,
      query: {
        tool: TENABLE_SC_ANALYSIS_TOOLS.VULN_DETAILS,
        filters: [{ filterName: 'severity', operator: '>', value: '2' }],
        startOffset: 0,
        endOffset: 1000,
      },
    })
  }

  /**
   * Get vulnerabilities by severity
   */
  async getVulnerabilitiesBySeverity(severity: string): Promise<ConnectorResponse<TenableScAnalysisResponse>> {
    return this.getVulnerabilities({
      severity,
    })
  }

  // ============================================
  // Policy Operations
  // ============================================

  /**
   * Get policies
   */
  async getPolicies(filters: GetPoliciesFilter = {}): Promise<ConnectorResponse<TenableScPoliciesResponse>> {
    const params: Record<string, unknown> = {}
    if (filters.fields) params.fields = filters.fields
    if (filters.filter) params.filter = filters.filter
    if (filters.sortField) params.sortField = filters.sortField
    if (filters.sortDir) params.sortDir = filters.sortDir

    return this.get<TenableScPoliciesResponse>(TENABLE_SC_API_PATHS.POLICIES, params)
  }

  /**
   * Get policy by ID
   */
  async getPolicyById(policyId: string): Promise<ConnectorResponse<TenableScPolicy>> {
    const response = await this.get<{ response: TenableScPolicy }>(TENABLE_SC_API_PATHS.POLICY_BY_ID(policyId))
    return {
      ...response,
      data: response.data?.response,
    }
  }

  // ============================================
  // User Operations
  // ============================================

  /**
   * Get users
   */
  async getUsers(filters: GetUsersFilter = {}): Promise<ConnectorResponse<TenableScUsersResponse>> {
    const params: Record<string, unknown> = {}
    if (filters.fields) params.fields = filters.fields
    if (filters.filter) params.filter = filters.filter
    if (filters.sortField) params.sortField = filters.sortField
    if (filters.sortDir) params.sortDir = filters.sortDir

    return this.get<TenableScUsersResponse>(TENABLE_SC_API_PATHS.USERS, params)
  }

  /**
   * Get user by ID
   */
  async getUserById(userId: string): Promise<ConnectorResponse<TenableScUser>> {
    const response = await this.get<{ response: TenableScUser }>(TENABLE_SC_API_PATHS.USER_BY_ID(userId))
    return {
      ...response,
      data: response.data?.response,
    }
  }

  /**
   * Create user
   */
  async createUser(userData: CreateUserParams): Promise<ConnectorResponse<TenableScUser>> {
    const response = await this.post<{ response: TenableScUser }>(TENABLE_SC_API_PATHS.USERS, userData)
    return {
      ...response,
      data: response.data?.response,
    }
  }

  /**
   * Update user
   */
  async updateUser(userId: string, userData: UpdateUserParams): Promise<ConnectorResponse<TenableScUser>> {
    const response = await this.put<{ response: TenableScUser }>(TENABLE_SC_API_PATHS.USER_BY_ID(userId), userData)
    return {
      ...response,
      data: response.data?.response,
    }
  }

  /**
   * Delete user
   */
  async deleteUser(userId: string): Promise<ConnectorResponse<{ success: boolean; message: string }>> {
    const response = await this.delete<unknown>(TENABLE_SC_API_PATHS.USER_BY_ID(userId))
    return {
      ...response,
      data: {
        success: response.success,
        message: response.success ? `User ${userId} deleted successfully` : 'Failed to delete user',
      },
    }
  }

  // ============================================
  // Role Operations
  // ============================================

  /**
   * Get roles
   */
  async getRoles(filters: GetRolesFilter = {}): Promise<ConnectorResponse<TenableScRolesResponse>> {
    const params: Record<string, unknown> = {}
    if (filters.fields) params.fields = filters.fields
    if (filters.filter) params.filter = filters.filter

    return this.get<TenableScRolesResponse>(TENABLE_SC_API_PATHS.ROLES, params)
  }

  /**
   * Get role by ID
   */
  async getRoleById(roleId: string): Promise<ConnectorResponse<TenableScRole>> {
    const response = await this.get<{ response: TenableScRole }>(TENABLE_SC_API_PATHS.ROLE_BY_ID(roleId))
    return {
      ...response,
      data: response.data?.response,
    }
  }

  // ============================================
  // Scan Operations
  // ============================================

  /**
   * Get scans
   */
  async getScans(filters: TenableScGetScansFilter = {}): Promise<ConnectorResponse<TenableScScansResponse>> {
    const params: Record<string, unknown> = {}
    if (filters.fields) params.fields = filters.fields
    if (filters.filter) params.filter = filters.filter
    if (filters.sortField) params.sortField = filters.sortField
    if (filters.sortDir) params.sortDir = filters.sortDir

    return this.get<TenableScScansResponse>(TENABLE_SC_API_PATHS.SCANS, params)
  }

  /**
   * Get scan by ID
   */
  async getScanById(scanId: string): Promise<ConnectorResponse<TenableScScan>> {
    const response = await this.get<{ response: TenableScScan }>(TENABLE_SC_API_PATHS.SCAN_BY_ID(scanId))
    return {
      ...response,
      data: response.data?.response,
    }
  }

  // ============================================
  // Scan Result Operations
  // ============================================

  /**
   * Get scan results
   */
  async getScanResults(filters: GetScanResultsFilter = {}): Promise<ConnectorResponse<TenableScScanResultsResponse>> {
    const params: Record<string, unknown> = {}
    if (filters.fields) params.fields = filters.fields
    if (filters.filter) params.filter = filters.filter
    if (filters.sortField) params.sortField = filters.sortField
    if (filters.sortDir) params.sortDir = filters.sortDir

    return this.get<TenableScScanResultsResponse>(TENABLE_SC_API_PATHS.SCAN_RESULTS, params)
  }

  /**
   * Get scan result by ID
   */
  async getScanResultById(resultId: string): Promise<ConnectorResponse<TenableScScanResult>> {
    const response = await this.get<{ response: TenableScScanResult }>(TENABLE_SC_API_PATHS.SCAN_RESULT_BY_ID(resultId))
    return {
      ...response,
      data: response.data?.response,
    }
  }

  // ============================================
  // Repository Operations
  // ============================================

  /**
   * Get repositories
   */
  async getRepositories(filters: GetRepositoriesFilter = {}): Promise<ConnectorResponse<TenableScRepositoryResponse>> {
    const params: Record<string, unknown> = {}
    if (filters.fields) params.fields = filters.fields
    if (filters.filter) params.filter = filters.filter

    return this.get<TenableScRepositoryResponse>(TENABLE_SC_API_PATHS.REPOSITORIES, params)
  }

  /**
   * Get repository by ID
   */
  async getRepositoryById(repoId: string): Promise<ConnectorResponse<TenableScRepository>> {
    const response = await this.get<{ response: TenableScRepository }>(TENABLE_SC_API_PATHS.REPOSITORY_BY_ID(repoId))
    return {
      ...response,
      data: response.data?.response,
    }
  }

  // ============================================
  // Statistics
  // ============================================

  /**
   * Get dashboard statistics
   */
  async getStats(): Promise<ConnectorResponse<TenableScStats>> {
    try {
      const [assetsResponse, vulnsResponse, criticalVulnsResponse, policiesResponse, usersResponse] = await Promise.all([
        this.getAssets({ fields: 'id,name,ipCount,vulns' }),
        this.getVulnerabilities({ endOffset: 10 }),
        this.getCriticalVulnerabilities(),
        this.getPolicies({ fields: 'id,name' }),
        this.getUsers({ fields: 'id,username,email,role' }),
      ])

      const stats: TenableScStats = {
        summary: {
          totalAssets: assetsResponse.data?.response?.usable?.length || 0,
          totalVulnerabilities: parseInt(vulnsResponse.data?.response?.totalRecords || '0'),
          criticalVulns: parseInt(criticalVulnsResponse.data?.response?.totalRecords || '0'),
          highVulns: 0, // Would need separate query
          totalPolicies: policiesResponse.data?.response?.usable?.length || 0,
          totalUsers: usersResponse.data?.response?.length || 0,
        },
        latestAssets: assetsResponse.data?.response?.usable?.slice(0, 5) || [],
        latestVulnerabilities: vulnsResponse.data?.response?.results?.slice(0, 5) || [],
      }

      return {
        success: true,
        data: stats,
        timestamp: new Date(),
        connector: 'tenable-sc',
      }
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to get statistics',
        timestamp: new Date(),
        connector: 'tenable-sc',
      }
    }
  }

  // ============================================
  // Utility Methods
  // ============================================

  /**
   * Map severity ID to severity name
   */
  getSeverityName(severityId: string): string {
    return TENABLE_SC_SEVERITY_MAP[severityId] || 'unknown'
  }
}
