// ============================================
// ENV HANDLER - Skillmine Connectors SDK
// ============================================
// Environment variable based secret management
// Fallback when Vault is not available
// ============================================

export interface EnvCredentials {
  [key: string]: string | undefined
}

export interface ConnectorEnvMap {
  qualys: {
    baseUrl: string
    username: string
    password: string
  }
  sentinelone: {
    baseUrl: string
    apiToken: string
  }
  checkpoint: {
    baseUrl: string
    username: string
    password: string
    domain?: string
  }
  manageengine: {
    baseUrl: string
    clientId: string
    clientSecret: string
    refreshToken: string
  }
  jira: {
    baseUrl: string
    email: string
    apiToken: string
  }
  zoho: {
    baseUrl: string
    clientId: string
    clientSecret: string
    refreshToken: string
  }
}

// ============================================
// Env Handler
// ============================================

export class EnvHandler {
  private prefix: string

  constructor(prefix = 'SKILLMINE') {
    this.prefix = prefix
  }

  // ============================================
  // Get Single Env Var
  // ============================================

  get(key: string, required = false): string | undefined {
    const fullKey = `${this.prefix}_${key.toUpperCase()}`
    const value = process.env[fullKey] ?? process.env[key]

    if (required && !value) {
      throw new Error(`Required environment variable '${fullKey}' is not set`)
    }

    return value
  }

  getRequired(key: string): string {
    return this.get(key, true) as string
  }

  // ============================================
  // Get Qualys Credentials
  // ============================================

  getQualysCredentials(): ConnectorEnvMap['qualys'] {
    return {
      baseUrl: this.getRequired('QUALYS_BASE_URL'),
      username: this.getRequired('QUALYS_USERNAME'),
      password: this.getRequired('QUALYS_PASSWORD'),
    }
  }

  // ============================================
  // Get SentinelOne Credentials
  // ============================================

  getSentinelOneCredentials(): ConnectorEnvMap['sentinelone'] {
    return {
      baseUrl: this.getRequired('SENTINELONE_BASE_URL'),
      apiToken: this.getRequired('SENTINELONE_API_TOKEN'),
    }
  }

  // ============================================
  // Get Checkpoint Credentials
  // ============================================

  getCheckpointCredentials(): ConnectorEnvMap['checkpoint'] {
    return {
      baseUrl: this.getRequired('CHECKPOINT_BASE_URL'),
      username: this.getRequired('CHECKPOINT_USERNAME'),
      password: this.getRequired('CHECKPOINT_PASSWORD'),
      domain: this.get('CHECKPOINT_DOMAIN'),
    }
  }

  // ============================================
  // Get ManageEngine Credentials
  // ============================================

  getManageEngineCredentials(): ConnectorEnvMap['manageengine'] {
    return {
      baseUrl: this.getRequired('MANAGEENGINE_BASE_URL'),
      clientId: this.getRequired('MANAGEENGINE_CLIENT_ID'),
      clientSecret: this.getRequired('MANAGEENGINE_CLIENT_SECRET'),
      refreshToken: this.getRequired('MANAGEENGINE_REFRESH_TOKEN'),
    }
  }

  // ============================================
  // Get Jira Credentials
  // ============================================

  getJiraCredentials(): ConnectorEnvMap['jira'] {
    return {
      baseUrl: this.getRequired('JIRA_BASE_URL'),
      email: this.getRequired('JIRA_EMAIL'),
      apiToken: this.getRequired('JIRA_API_TOKEN'),
    }
  }

  // ============================================
  // Get Zoho Credentials
  // ============================================

  getZohoCredentials(): ConnectorEnvMap['zoho'] {
    return {
      baseUrl: this.getRequired('ZOHO_BASE_URL'),
      clientId: this.getRequired('ZOHO_CLIENT_ID'),
      clientSecret: this.getRequired('ZOHO_CLIENT_SECRET'),
      refreshToken: this.getRequired('ZOHO_REFRESH_TOKEN'),
    }
  }

  // ============================================
  // Validate All Required Env Vars
  // ============================================

  validateConnector(connectorName: keyof ConnectorEnvMap): boolean {
    const requiredVars: Record<keyof ConnectorEnvMap, string[]> = {
      qualys: ['QUALYS_BASE_URL', 'QUALYS_USERNAME', 'QUALYS_PASSWORD'],
      sentinelone: ['SENTINELONE_BASE_URL', 'SENTINELONE_API_TOKEN'],
      checkpoint: ['CHECKPOINT_BASE_URL', 'CHECKPOINT_USERNAME', 'CHECKPOINT_PASSWORD'],
      manageengine: ['MANAGEENGINE_BASE_URL', 'MANAGEENGINE_CLIENT_ID', 'MANAGEENGINE_CLIENT_SECRET', 'MANAGEENGINE_REFRESH_TOKEN'],
      jira: ['JIRA_BASE_URL', 'JIRA_EMAIL', 'JIRA_API_TOKEN'],
      zoho: ['ZOHO_BASE_URL', 'ZOHO_CLIENT_ID', 'ZOHO_CLIENT_SECRET', 'ZOHO_REFRESH_TOKEN'],
    }

    const vars = requiredVars[connectorName]
    const missing = vars.filter(
      (v) => !process.env[`${this.prefix}_${v}`] && !process.env[v],
    )

    if (missing.length > 0) {
      console.warn(`Missing env vars for ${connectorName}: ${missing.join(', ')}`)
      return false
    }

    return true
  }

  // ============================================
  // Get .env.example content
  // ============================================

  static getEnvExample(): string {
    return `# Skillmine Connectors SDK - Environment Variables

# Qualys
SKILLMINE_QUALYS_BASE_URL=https://qualysapi.qualys.com
SKILLMINE_QUALYS_USERNAME=your_username
SKILLMINE_QUALYS_PASSWORD=your_password

# SentinelOne
SKILLMINE_SENTINELONE_BASE_URL=https://your-instance.sentinelone.net
SKILLMINE_SENTINELONE_API_TOKEN=your_api_token

# Checkpoint
SKILLMINE_CHECKPOINT_BASE_URL=https://your-checkpoint-mgmt
SKILLMINE_CHECKPOINT_USERNAME=admin
SKILLMINE_CHECKPOINT_PASSWORD=your_password
SKILLMINE_CHECKPOINT_DOMAIN=your_domain

# ManageEngine
SKILLMINE_MANAGEENGINE_BASE_URL=https://your-manageengine
SKILLMINE_MANAGEENGINE_CLIENT_ID=your_client_id
SKILLMINE_MANAGEENGINE_CLIENT_SECRET=your_client_secret
SKILLMINE_MANAGEENGINE_REFRESH_TOKEN=your_refresh_token

# Jira
SKILLMINE_JIRA_BASE_URL=https://your-org.atlassian.net
SKILLMINE_JIRA_EMAIL=your@email.com
SKILLMINE_JIRA_API_TOKEN=your_api_token

# Zoho
SKILLMINE_ZOHO_BASE_URL=https://www.zohoapis.com
SKILLMINE_ZOHO_CLIENT_ID=your_client_id
SKILLMINE_ZOHO_CLIENT_SECRET=your_client_secret
SKILLMINE_ZOHO_REFRESH_TOKEN=your_refresh_token
`
  }
}

// ============================================
// Global Env Handler
// ============================================

export const envHandler = new EnvHandler('SKILLMINE')