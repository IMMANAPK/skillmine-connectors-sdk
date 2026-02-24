// ============================================
// MCP SERVER - Complyment Connectors SDK
// ============================================
// Model Context Protocol - AI Agents can use
// connectors directly via MCP standard
// ============================================

export interface MCPTool {
  name: string
  description: string
  inputSchema: {
    type: 'object'
    properties: Record<string, MCPToolProperty>
    required?: string[]
  }
  handler: (input: Record<string, unknown>) => Promise<MCPToolResult>
}

export interface MCPToolProperty {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object'
  description: string
  enum?: string[]
  items?: { type: string }
}

export interface MCPToolResult {
  content: Array<{
    type: 'text' | 'json'
    text?: string
    data?: unknown
  }>
  isError?: boolean
}

export interface MCPServerOptions {
  name?: string
  version?: string
  description?: string
}

// ============================================
// MCP Server
// ============================================

export class MCPServer {
  private tools: Map<string, MCPTool> = new Map()
  private readonly name: string
  private readonly version: string
  private readonly description: string

  constructor(options?: MCPServerOptions) {
    this.name = options?.name ?? 'complyment-connectors-mcp'
    this.version = options?.version ?? '1.0.0'
    this.description = options?.description ?? 'Complyment Connectors SDK MCP Server'
  }

  // ============================================
  // Register Tool
  // ============================================

  registerTool(tool: MCPTool): void {
    this.tools.set(tool.name, tool)
  }

  // ============================================
  // Register Connector Tools (Auto-register)
  // ============================================

  registerConnectorTools(
    connectorName: string,
    methods: Array<{
      name: string
      description: string
      params?: Record<string, MCPToolProperty>
      handler: (params: Record<string, unknown>) => Promise<unknown>
    }>,
  ): void {
    for (const method of methods) {
      this.registerTool({
        name: `${connectorName}_${method.name}`,
        description: method.description,
        inputSchema: {
          type: 'object',
          properties: method.params ?? {},
          required: [],
        },
        handler: async (input) => {
          try {
            const result = await method.handler(input)
            return {
              content: [{ type: 'json', data: result }],
            }
          } catch (error) {
            return {
              content: [{
                type: 'text',
                text: error instanceof Error ? error.message : 'Unknown error',
              }],
              isError: true,
            }
          }
        },
      })
    }
  }

  // ============================================
  // Execute Tool
  // ============================================

  async executeTool(
    name: string,
    input: Record<string, unknown>,
  ): Promise<MCPToolResult> {
    const tool = this.tools.get(name)

    if (!tool) {
      return {
        content: [{ type: 'text', text: `Tool '${name}' not found` }],
        isError: true,
      }
    }

    try {
      return await tool.handler(input)
    } catch (error) {
      return {
        content: [{
          type: 'text',
          text: error instanceof Error ? error.message : 'Tool execution failed',
        }],
        isError: true,
      }
    }
  }

  // ============================================
  // List Tools (MCP Protocol)
  // ============================================

  listTools(): MCPTool[] {
    return Array.from(this.tools.values())
  }

  getToolByName(name: string): MCPTool | undefined {
    return this.tools.get(name)
  }

  // ============================================
  // Server Info (MCP Protocol)
  // ============================================

  getServerInfo() {
    return {
      name: this.name,
      version: this.version,
      description: this.description,
      toolCount: this.tools.size,
    }
  }

  // ============================================
  // Generate MCP Manifest
  // ============================================

  generateManifest() {
    return {
      schema_version: '1.0',
      name_for_human: this.name,
      name_for_model: this.name.replace(/-/g, '_'),
      description_for_human: this.description,
      description_for_model: this.description,
      api: {
        type: 'mcp',
        version: this.version,
      },
      tools: Array.from(this.tools.values()).map((tool) => ({
        name: tool.name,
        description: tool.description,
        input_schema: tool.inputSchema,
      })),
    }
  }
}

// ============================================
// Qualys MCP Tools Factory
// ============================================

export function createQualysMCPTools(qualysConnector: {
  getAssets: (filter?: unknown) => Promise<unknown>
  getVulnerabilities: (filter?: unknown) => Promise<unknown>
  getCriticalVulnerabilities: () => Promise<unknown>
  getScans: (filter?: unknown) => Promise<unknown>
  healthCheck: () => Promise<unknown>
}) {
  return [
    {
      name: 'get_assets',
      description: 'Get all assets from Qualys vulnerability management',
      params: {
        limit: { type: 'number' as const, description: 'Number of assets to return' },
        hostname: { type: 'string' as const, description: 'Filter by hostname' },
      },
      handler: async (params: Record<string, unknown>) =>
        qualysConnector.getAssets(params),
    },
    {
      name: 'get_vulnerabilities',
      description: 'Get vulnerabilities from Qualys',
      params: {
        severity: { type: 'array' as const, description: 'Filter by severity levels (1-5)', items: { type: 'number' } },
        status: { type: 'string' as const, description: 'Filter by status (Active, Fixed, New)' },
      },
      handler: async (params: Record<string, unknown>) =>
        qualysConnector.getVulnerabilities(params),
    },
    {
      name: 'get_critical_vulnerabilities',
      description: 'Get only critical and high severity active vulnerabilities',
      handler: async () => qualysConnector.getCriticalVulnerabilities(),
    },
    {
      name: 'health_check',
      description: 'Check Qualys connector health and connection status',
      handler: async () => qualysConnector.healthCheck(),
    },
  ]
}

// ============================================
// SentinelOne MCP Tools Factory
// ============================================

export function createSentinelOneMCPTools(s1Connector: {
  getAgents: (filter?: unknown) => Promise<unknown>
  getThreats: (filter?: unknown) => Promise<unknown>
  getCriticalThreats: () => Promise<unknown>
  quarantineThreat: (id: string) => Promise<unknown>
  healthCheck: () => Promise<unknown>
}) {
  return [
    {
      name: 'get_agents',
      description: 'Get all endpoint agents from SentinelOne',
      params: {
        infected: { type: 'boolean' as const, description: 'Filter infected agents only' },
        limit: { type: 'number' as const, description: 'Number of agents to return' },
      },
      handler: async (params: Record<string, unknown>) =>
        s1Connector.getAgents(params),
    },
    {
      name: 'get_threats',
      description: 'Get threats detected by SentinelOne',
      params: {
        severity: { type: 'string' as const, description: 'Filter by severity (critical, high, medium, low)' },
        status: { type: 'string' as const, description: 'Filter by status (active, mitigated, resolved)' },
      },
      handler: async (params: Record<string, unknown>) =>
        s1Connector.getThreats(params),
    },
    {
      name: 'quarantine_threat',
      description: 'Quarantine a specific threat by ID',
      params: {
        threatId: { type: 'string' as const, description: 'Threat ID to quarantine' },
      },
      handler: async (params: Record<string, unknown>) =>
        s1Connector.quarantineThreat(params['threatId'] as string),
    },
    {
      name: 'health_check',
      description: 'Check SentinelOne connector health',
      handler: async () => s1Connector.healthCheck(),
    },
  ]
}

// ============================================
// Global MCP Server Instance
// ============================================

export const mcpServer = new MCPServer({
  name: 'complyment-connectors-mcp',
  version: '1.0.0',
  description: 'AI Agent interface for Complyment security connectors',
})