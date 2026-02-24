// ============================================
// ZOHO CONNECTOR - Complyment Connectors SDK
// ============================================

import { BaseConnector } from '../../core/BaseConnector'
import {
  ConnectorConfig,
  ConnectorResponse,
  AuthType,
  LogLevel,
  PaginatedResponse,
} from '../../core/types'
import {
  ZohoConfig,
  ZohoContact,
  ZohoContactFilter,
  ZohoContactListResponse,
  ZohoLead,
  ZohoLeadFilter,
  ZohoAccount,
  ZohoDeal,
  ZohoDealFilter,
  ZohoTask,
  ZohoSearchResponse,
} from './types'

export class ZohoConnector extends BaseConnector {
  private clientId: string
  private clientSecret: string
  private refreshToken: string
  private accountsUrl: string

  constructor(zohoConfig: ZohoConfig) {
    const config: ConnectorConfig = {
      name: 'zoho',
      baseUrl: zohoConfig.baseUrl,
      auth: {
        type: AuthType.OAUTH2,
        clientId: zohoConfig.clientId,
        clientSecret: zohoConfig.clientSecret,
        tokenUrl: `${zohoConfig.accountsUrl ?? 'https://accounts.zoho.com'}/oauth/v2/token`,
      },
      timeout: zohoConfig.timeout ?? 30000,
      retries: zohoConfig.retries ?? 3,
      cache: zohoConfig.cache,
      dryRun: zohoConfig.dryRun,
      logger: LogLevel.INFO,
    }
    super(config)
    this.clientId = zohoConfig.clientId
    this.clientSecret = zohoConfig.clientSecret
    this.refreshToken = zohoConfig.refreshToken
    this.accountsUrl = zohoConfig.accountsUrl ?? 'https://accounts.zoho.com'
  }

  // ============================================
  // Auth - OAuth2 Refresh Token
  // ============================================

  async authenticate(): Promise<void> {
    const response = await this.post<{
      access_token: string
      expires_in: number
    }>(`${this.accountsUrl}/oauth/v2/token`, {
      grant_type: 'refresh_token',
      client_id: this.clientId,
      client_secret: this.clientSecret,
      refresh_token: this.refreshToken,
    })

    if (response.data) {
      this.setToken(response.data.access_token, response.data.expires_in)
    }
  }

  async testConnection(): Promise<boolean> {
    try {
      await this.authenticate()
      await this.get('/crm/v3/Contacts', { per_page: 1 })
      return true
    } catch {
      return false
    }
  }

  // ============================================
  // Contacts
  // ============================================

  async getContacts(
    filter?: ZohoContactFilter,
  ): Promise<ConnectorResponse<PaginatedResponse<ZohoContact>>> {
    const params: Record<string, unknown> = {
      page: filter?.page ?? 1,
      per_page: filter?.perPage ?? 50,
    }

    if (filter?.sortBy) params['sort_by'] = filter.sortBy
    if (filter?.sortOrder) params['sort_order'] = filter.sortOrder

    const response = await this.get<ZohoContactListResponse>(
      '/crm/v3/Contacts',
      params,
      true,
    )

    if (response.data) {
      const paginated = this.buildPaginatedResponse(
        response.data.data,
        response.data.info.count,
        { page: filter?.page, limit: filter?.perPage },
      )
      return { ...response, data: paginated }
    }

    return response as unknown as ConnectorResponse<PaginatedResponse<ZohoContact>>
  }

  async getContactById(
    contactId: string,
  ): Promise<ConnectorResponse<ZohoContact>> {
    return this.get<ZohoContact>(`/crm/v3/Contacts/${contactId}`)
  }

  async createContact(
    contact: Partial<ZohoContact>,
  ): Promise<ConnectorResponse<ZohoContact>> {
    return this.post<ZohoContact>('/crm/v3/Contacts', {
      data: [contact],
    })
  }

  async updateContact(
    contactId: string,
    updates: Partial<ZohoContact>,
  ): Promise<ConnectorResponse<ZohoContact>> {
    return this.put<ZohoContact>(`/crm/v3/Contacts/${contactId}`, {
      data: [updates],
    })
  }

  async deleteContact(contactId: string): Promise<ConnectorResponse<void>> {
    return this.delete(`/crm/v3/Contacts/${contactId}`)
  }

  // ============================================
  // Leads
  // ============================================

  async getLeads(
    filter?: ZohoLeadFilter,
  ): Promise<ConnectorResponse<PaginatedResponse<ZohoLead>>> {
    const params: Record<string, unknown> = {
      page: filter?.page ?? 1,
      per_page: filter?.perPage ?? 50,
    }

    if (filter?.sortBy) params['sort_by'] = filter.sortBy
    if (filter?.sortOrder) params['sort_order'] = filter.sortOrder

    const response = await this.get<ZohoContactListResponse>(
      '/crm/v3/Leads',
      params,
      true,
    )

    if (response.data) {
      const paginated = this.buildPaginatedResponse(
        response.data.data as unknown as ZohoLead[],
        response.data.info.count,
        { page: filter?.page, limit: filter?.perPage },
      )
      return { ...response, data: paginated }
    }

    return response as unknown as ConnectorResponse<PaginatedResponse<ZohoLead>>
  }

  async getLeadById(
    leadId: string,
  ): Promise<ConnectorResponse<ZohoLead>> {
    return this.get<ZohoLead>(`/crm/v3/Leads/${leadId}`)
  }

  async createLead(
    lead: Partial<ZohoLead>,
  ): Promise<ConnectorResponse<ZohoLead>> {
    return this.post<ZohoLead>('/crm/v3/Leads', { data: [lead] })
  }

  async convertLead(
    leadId: string,
    accountName: string,
  ): Promise<ConnectorResponse<void>> {
    return this.post(`/crm/v3/Leads/${leadId}/actions/convert`, {
      data: [{ Accounts: { Account_Name: accountName } }],
    })
  }

  // ============================================
  // Accounts
  // ============================================

  async getAccounts(
    page = 1,
    perPage = 50,
  ): Promise<ConnectorResponse<PaginatedResponse<ZohoAccount>>> {
    const response = await this.get<ZohoContactListResponse>(
      '/crm/v3/Accounts',
      { page, per_page: perPage },
      true,
    )

    if (response.data) {
      const paginated = this.buildPaginatedResponse(
        response.data.data as unknown as ZohoAccount[],
        response.data.info.count,
        { page, limit: perPage },
      )
      return { ...response, data: paginated }
    }

    return response as unknown as ConnectorResponse<PaginatedResponse<ZohoAccount>>
  }

  async getAccountById(
    accountId: string,
  ): Promise<ConnectorResponse<ZohoAccount>> {
    return this.get<ZohoAccount>(`/crm/v3/Accounts/${accountId}`)
  }

  async createAccount(
    account: Partial<ZohoAccount>,
  ): Promise<ConnectorResponse<ZohoAccount>> {
    return this.post<ZohoAccount>('/crm/v3/Accounts', { data: [account] })
  }

  // ============================================
  // Deals
  // ============================================

  async getDeals(
    filter?: ZohoDealFilter,
  ): Promise<ConnectorResponse<PaginatedResponse<ZohoDeal>>> {
    const params: Record<string, unknown> = {
      page: filter?.page ?? 1,
      per_page: filter?.perPage ?? 50,
    }

    if (filter?.sortBy) params['sort_by'] = filter.sortBy
    if (filter?.sortOrder) params['sort_order'] = filter.sortOrder

    const response = await this.get<ZohoContactListResponse>(
      '/crm/v3/Deals',
      params,
      true,
    )

    if (response.data) {
      const paginated = this.buildPaginatedResponse(
        response.data.data as unknown as ZohoDeal[],
        response.data.info.count,
        { page: filter?.page, limit: filter?.perPage },
      )
      return { ...response, data: paginated }
    }

    return response as unknown as ConnectorResponse<PaginatedResponse<ZohoDeal>>
  }

  async getDealById(
    dealId: string,
  ): Promise<ConnectorResponse<ZohoDeal>> {
    return this.get<ZohoDeal>(`/crm/v3/Deals/${dealId}`)
  }

  async createDeal(
    deal: Partial<ZohoDeal>,
  ): Promise<ConnectorResponse<ZohoDeal>> {
    return this.post<ZohoDeal>('/crm/v3/Deals', { data: [deal] })
  }

  async updateDeal(
    dealId: string,
    updates: Partial<ZohoDeal>,
  ): Promise<ConnectorResponse<ZohoDeal>> {
    return this.put<ZohoDeal>(`/crm/v3/Deals/${dealId}`, {
      data: [updates],
    })
  }

  // ============================================
  // Tasks
  // ============================================

  async getTasks(): Promise<ConnectorResponse<ZohoTask[]>> {
    return this.get<ZohoTask[]>('/crm/v3/Tasks', {
      page: 1,
      per_page: 100,
    })
  }

  async createTask(
    task: Partial<ZohoTask>,
  ): Promise<ConnectorResponse<ZohoTask>> {
    return this.post<ZohoTask>('/crm/v3/Tasks', { data: [task] })
  }

  // ============================================
  // Search
  // ============================================

  async searchContacts(
    query: string,
  ): Promise<ConnectorResponse<ZohoSearchResponse<ZohoContact>>> {
    return this.get<ZohoSearchResponse<ZohoContact>>(
      '/crm/v3/Contacts/search',
      { criteria: query },
    )
  }

  async searchLeads(
    query: string,
  ): Promise<ConnectorResponse<ZohoSearchResponse<ZohoLead>>> {
    return this.get<ZohoSearchResponse<ZohoLead>>(
      '/crm/v3/Leads/search',
      { criteria: query },
    )
  }

  async searchDeals(
    query: string,
  ): Promise<ConnectorResponse<ZohoSearchResponse<ZohoDeal>>> {
    return this.get<ZohoSearchResponse<ZohoDeal>>(
      '/crm/v3/Deals/search',
      { criteria: query },
    )
  }

  // ============================================
  // Bulk Operations
  // ============================================

  async bulkCreateContacts(
    contacts: Partial<ZohoContact>[],
  ): Promise<ConnectorResponse<ZohoContact[]>> {
    // Zoho allows max 100 records per bulk request
    const chunks = this.chunkArray(contacts, 100)
    const results: ZohoContact[] = []

    for (const chunk of chunks) {
      const response = await this.post<ZohoContact[]>(
        '/crm/v3/Contacts',
        { data: chunk },
      )
      if (response.data) results.push(...response.data)
    }

    return {
      success: true,
      data: results,
      timestamp: new Date(),
      connector: 'zoho',
    }
  }

  // ============================================
  // Private Helpers
  // ============================================

  private chunkArray<T>(array: T[], size: number): T[][] {
    const chunks: T[][] = []
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size))
    }
    return chunks
  }
}