// ============================================
// CHECKPOINT CONNECTOR - Complyment Connectors SDK
// ============================================

import { BaseConnector } from '../../core/BaseConnector'
import {
  ConnectorConfig,
  ConnectorResponse,
  NormalizedThreat,
  NormalizedAsset,
  AuthType,
  LogLevel,
} from '../../core/types'
import {
  CheckpointConfig,
  CheckpointSession,
  CheckpointPolicy,
  CheckpointRule,
  CheckpointRuleFilter,
  CheckpointHost,
  CheckpointHostFilter,
  CheckpointNetwork,
  CheckpointGroup,
  CheckpointThreat,
  CheckpointLog,
  CheckpointLogFilter,
  CheckpointGateway,
} from './types'

export class CheckpointConnector extends BaseConnector {
  private session?: CheckpointSession
  private domain?: string

  constructor(cpConfig: CheckpointConfig) {
    const config: ConnectorConfig = {
      name: 'checkpoint',
      baseUrl: cpConfig.baseUrl,
      auth: {
        type: AuthType.BASIC,
        username: cpConfig.username,
        password: cpConfig.password,
      },
      timeout: cpConfig.timeout ?? 30000,
      retries: cpConfig.retries ?? 3,
      cache: cpConfig.cache,
      dryRun: cpConfig.dryRun,
      logger: LogLevel.INFO,
    }
    super(config)
    this.domain = cpConfig.domain
  }

  // ============================================
  // Auth - Checkpoint uses session-based auth
  // ============================================

  async authenticate(): Promise<void> {
    const response = await this.post<CheckpointSession>('/web_api/login', {
      user: (this.config as ConnectorConfig & { auth: { username: string; password: string } }).auth,
      password: (this.config as ConnectorConfig & { auth: { username: string; password: string } }).auth,
      ...(this.domain && { domain: this.domain }),
    })

    if (response.data) {
      this.session = response.data
      // Inject session ID into future requests
      this.httpClient.defaults.headers.common['X-chkp-sid'] = this.session.sid
    }
  }

  async logout(): Promise<void> {
    if (this.session) {
      await this.post('/web_api/logout', {})
      this.session = undefined
      delete this.httpClient.defaults.headers.common['X-chkp-sid']
    }
  }

  async testConnection(): Promise<boolean> {
    try {
      await this.authenticate()
      return !!this.session
    } catch {
      return false
    }
  }

  // ============================================
  // Policy Management
  // ============================================

  async getPolicies(): Promise<ConnectorResponse<CheckpointPolicy[]>> {
    return this.post<CheckpointPolicy[]>('/web_api/show-access-rulebase', {
      limit: 100,
      offset: 0,
    })
  }

  async getRules(
    filter?: CheckpointRuleFilter,
  ): Promise<ConnectorResponse<CheckpointRule[]>> {
    return this.post<CheckpointRule[]>('/web_api/show-access-rulebase', {
      name: filter?.policyName ?? 'Network',
      limit: filter?.limit ?? 50,
      offset: filter?.offset ?? 0,
    })
  }

  async addRule(
    policyName: string,
    rule: Partial<CheckpointRule>,
  ): Promise<ConnectorResponse<CheckpointRule>> {
    return this.post<CheckpointRule>('/web_api/add-access-rule', {
      layer: policyName,
      ...rule,
    })
  }

  async updateRule(
    ruleUid: string,
    policyName: string,
    updates: Partial<CheckpointRule>,
  ): Promise<ConnectorResponse<CheckpointRule>> {
    return this.post<CheckpointRule>('/web_api/set-access-rule', {
      uid: ruleUid,
      layer: policyName,
      ...updates,
    })
  }

  async deleteRule(
    ruleUid: string,
    policyName: string,
  ): Promise<ConnectorResponse<void>> {
    return this.post('/web_api/delete-access-rule', {
      uid: ruleUid,
      layer: policyName,
    })
  }

  async publishChanges(): Promise<ConnectorResponse<void>> {
    return this.post('/web_api/publish', {})
  }

  async discardChanges(): Promise<ConnectorResponse<void>> {
    return this.post('/web_api/discard', {})
  }

  async installPolicy(
    policyName: string,
    targets: string[],
  ): Promise<ConnectorResponse<void>> {
    return this.post('/web_api/install-policy', {
      'policy-package': policyName,
      targets,
    })
  }

  // ============================================
  // Network Objects
  // ============================================

  async getHosts(
    filter?: CheckpointHostFilter,
  ): Promise<ConnectorResponse<CheckpointHost[]>> {
    return this.post<CheckpointHost[]>('/web_api/show-hosts', {
      limit: filter?.limit ?? 50,
      offset: filter?.offset ?? 0,
      ...(filter?.name && { filter: filter.name }),
    }, true)
  }

  async addHost(
    name: string,
    ipAddress: string,
    comments?: string,
  ): Promise<ConnectorResponse<CheckpointHost>> {
    return this.post<CheckpointHost>('/web_api/add-host', {
      name,
      'ip-address': ipAddress,
      ...(comments && { comments }),
    })
  }

  async deleteHost(uid: string): Promise<ConnectorResponse<void>> {
    return this.post('/web_api/delete-host', { uid })
  }

  async getNetworks(): Promise<ConnectorResponse<CheckpointNetwork[]>> {
    return this.post<CheckpointNetwork[]>('/web_api/show-networks', {
      limit: 100,
    }, true)
  }

  async getGroups(): Promise<ConnectorResponse<CheckpointGroup[]>> {
    return this.post<CheckpointGroup[]>('/web_api/show-groups', {
      limit: 100,
    }, true)
  }

  // ============================================
  // Threat Prevention
  // ============================================

  async getThreats(): Promise<ConnectorResponse<CheckpointThreat[]>> {
    return this.post<CheckpointThreat[]>(
      '/web_api/show-threat-protections',
      { limit: 100 },
      true,
    )
  }

  async blockThreat(threatUid: string): Promise<ConnectorResponse<void>> {
    return this.post('/web_api/set-threat-protection', {
      uid: threatUid,
      action: 'Prevent',
    })
  }

  // ============================================
  // Logs
  // ============================================

  async getLogs(
    filter?: CheckpointLogFilter,
  ): Promise<ConnectorResponse<CheckpointLog[]>> {
    return this.post<CheckpointLog[]>('/web_api/show-logs', {
      'time-frame': 'last-hour',
      limit: filter?.limit ?? 50,
      ...(filter?.startTime && { 'start-time': filter.startTime }),
      ...(filter?.endTime && { 'end-time': filter.endTime }),
      ...(filter?.sourceIp && { 'source-ip': filter.sourceIp }),
      ...(filter?.destinationIp && { 'destination-ip': filter.destinationIp }),
      ...(filter?.action && { action: filter.action }),
    })
  }

  // ============================================
  // Gateways
  // ============================================

  async getGateways(): Promise<ConnectorResponse<CheckpointGateway[]>> {
    return this.post<CheckpointGateway[]>(
      '/web_api/show-gateways-and-servers',
      { limit: 100 },
      true,
    )
  }

  async getGatewayStatus(
    gatewayUid: string,
  ): Promise<ConnectorResponse<CheckpointGateway>> {
    return this.post<CheckpointGateway>('/web_api/show-gateway', {
      uid: gatewayUid,
    })
  }

  // ============================================
  // Normalization
  // ============================================

  async getNormalizedThreats(): Promise<ConnectorResponse<NormalizedThreat[]>> {
    const response = await this.getThreats()

    if (!response.data) return { ...response, data: [] }

    const normalized: NormalizedThreat[] = response.data.map((threat) => ({
      id: threat.uid,
      name: threat.name,
      severity: threat.severity.toLowerCase() as 'critical' | 'high' | 'medium' | 'low',
      status: 'active',
      affectedAsset: threat.affectedSystems.join(', '),
      source: 'checkpoint',
      detectedAt: new Date(),
      raw: threat,
    }))

    return { ...response, data: normalized }
  }

  async getNormalizedAssets(): Promise<ConnectorResponse<NormalizedAsset[]>> {
    const response = await this.getGateways()

    if (!response.data) return { ...response, data: [] }

    const normalized: NormalizedAsset[] = response.data.map((gateway) => ({
      id: gateway.uid,
      hostname: gateway.name,
      ipAddress: gateway.ipAddress,
      os: gateway.osName,
      type: 'network',
      source: 'checkpoint',
      lastSeen: new Date(gateway.lastUpdateTime),
      raw: gateway,
    }))

    return { ...response, data: normalized }
  }
}