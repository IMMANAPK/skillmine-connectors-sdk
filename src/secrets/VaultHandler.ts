// ============================================
// VAULT HANDLER - Complyment Connectors SDK
// ============================================
// HashiCorp Vault integration for secrets
// ============================================

import axios, { AxiosInstance } from 'axios'

export interface VaultConfig {
  vaultUrl: string
  token: string
  namespace?: string        // Vault Enterprise namespace
  timeout?: number
}

export interface VaultSecret {
  path: string
  data: Record<string, string>
  version?: number
  createdAt?: Date
  expiresAt?: Date
}

export interface VaultAuthResponse {
  token: string
  leaseDuration: number
  renewable: boolean
}

// ============================================
// Vault Handler
// ============================================

export class VaultHandler {
  private client: AxiosInstance
  private token: string

  constructor(config: VaultConfig) {
    this.token = config.token
    this.client = axios.create({
      baseURL: config.vaultUrl,
      timeout: config.timeout ?? 10000,
      headers: {
        'X-Vault-Token': config.token,
        'Content-Type': 'application/json',
        ...(config.namespace && { 'X-Vault-Namespace': config.namespace }),
      },
    })
  }

  // ============================================
  // Read Secret
  // ============================================

  async readSecret(path: string): Promise<VaultSecret> {
    const response = await this.client.get(`/v1/${path}`)
    const data = response.data

    return {
      path,
      data: data.data?.data ?? data.data ?? {},
      version: data.data?.metadata?.version,
      createdAt: data.data?.metadata?.created_time
        ? new Date(data.data.metadata.created_time)
        : undefined,
    }
  }

  // ============================================
  // Write Secret
  // ============================================

  async writeSecret(
    path: string,
    data: Record<string, string>,
  ): Promise<void> {
    await this.client.post(`/v1/${path}`, { data })
  }

  // ============================================
  // Delete Secret
  // ============================================

  async deleteSecret(path: string): Promise<void> {
    await this.client.delete(`/v1/${path}`)
  }

  // ============================================
  // List Secrets
  // ============================================

  async listSecrets(path: string): Promise<string[]> {
    const response = await this.client.request({
      method: 'LIST',
      url: `/v1/${path}`,
    })
    return response.data?.data?.keys ?? []
  }

  // ============================================
  // Get Connector Credentials
  // ============================================

  async getConnectorCredentials(
    connectorName: string,
  ): Promise<Record<string, string>> {
    try {
      const secret = await this.readSecret(
        `secret/data/connectors/${connectorName}`,
      )
      return secret.data
    } catch {
      throw new Error(
        `Failed to fetch credentials for connector: ${connectorName}`,
      )
    }
  }

  // ============================================
  // Health Check
  // ============================================

  async healthCheck(): Promise<boolean> {
    try {
      await this.client.get('/v1/sys/health')
      return true
    } catch {
      return false
    }
  }

  // ============================================
  // Renew Token
  // ============================================

  async renewToken(): Promise<VaultAuthResponse> {
    const response = await this.client.post('/v1/auth/token/renew-self')
    return {
      token: response.data.auth.client_token,
      leaseDuration: response.data.auth.lease_duration,
      renewable: response.data.auth.renewable,
    }
  }
}