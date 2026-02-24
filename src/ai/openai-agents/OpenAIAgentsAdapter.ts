// ============================================
// OPENAI AGENTS ADAPTER - Complyment Connectors SDK
// ============================================
// Convert connectors to OpenAI Agents SDK tools
// Compatible with OpenAI Agents SDK 2025/2026
// ============================================

export interface OpenAIAgentTool {
  type: 'function'
  function: {
    name: string
    description: string
    parameters: {
      type: 'object'
      properties: Record<string, OpenAIToolProperty>
      required?: string[]
    }
    strict?: boolean
  }
  execute: (params: Record<string, unknown>) => Promise<string>
}

export interface OpenAIToolProperty {
  type: 'string' | 'number' | 'boolean' | 'array' | 'object'
  description: string
  enum?: string[]
  items?: { type: string }
}

export interface OpenAIAgentDefinition {
  name: string
  instructions: string
  tools: OpenAIAgentTool[]
  model?: string
}

// ============================================
// OpenAI Agents Adapter
// ============================================

export class OpenAIAgentsAdapter {

  // ============================================
  // Create Single Tool
  // ============================================

  static createTool(options: {
    name: string
    description: string
    parameters?: Record<string, OpenAIToolProperty>
    required?: string[]
    strict?: boolean
    execute: (params: Record<string, unknown>) => Promise<unknown>
  }): OpenAIAgentTool {
    return {
      type: 'function',
      function: {
        name: options.name,
        description: options.description,
        parameters: {
          type: 'object',
          properties: options.parameters ?? {},
          required: options.required ?? [],
        },
        strict: options.strict ?? false,
      },
      execute: async (params) => {
        try {
          const result = await options.execute(params)
          return JSON.stringify(result, null, 2)
        } catch (error) {
          return JSON.stringify({
            error: error instanceof Error ? error.message : 'Tool failed',
            success: false,
          })
        }
      },
    }
  }

  // ============================================
  // Security Analyst Agent
  // ============================================

  static createSecurityAnalystAgent(connectors: {
    qualys?: {
      getVulnerabilities: (filter?: unknown) => Promise<unknown>
      getCriticalVulnerabilities: () => Promise<unknown>
      getAssets: (filter?: unknown) => Promise<unknown>
    }
    sentinelone?: {
      getThreats: (filter?: unknown) => Promise<unknown>
      getCriticalThreats: () => Promise<unknown>
      quarantineThreat: (id: string) => Promise<unknown>
    }
    jira?: {
      createSecurityTicket: (
        projectKey: string,
        title: string,
        description: string,
        severity: string,
        source: string,
      ) => Promise<unknown>
    }
  }): OpenAIAgentDefinition {
    const tools: OpenAIAgentTool[] = []

    // Qualys tools
    if (connectors.qualys) {
      tools.push(
        this.createTool({
          name: 'get_vulnerabilities',
          description: 'Get vulnerability scan results from Qualys',
          parameters: {
            severity: { type: 'array', description: 'Severity levels 1-5', items: { type: 'number' } },
            status: { type: 'string', description: 'Status filter', enum: ['Active', 'Fixed', 'New'] },
          },
          execute: async (params) => connectors.qualys!.getVulnerabilities(params),
        }),

        this.createTool({
          name: 'get_critical_vulnerabilities',
          description: 'Get only critical and high severity vulnerabilities',
          execute: async () => connectors.qualys!.getCriticalVulnerabilities(),
        }),

        this.createTool({
          name: 'get_assets',
          description: 'Get IT assets from Qualys',
          parameters: {
            hostname: { type: 'string', description: 'Filter by hostname' },
            limit: { type: 'number', description: 'Max results' },
          },
          execute: async (params) => connectors.qualys!.getAssets(params),
        }),
      )
    }

    // SentinelOne tools
    if (connectors.sentinelone) {
      tools.push(
        this.createTool({
          name: 'get_threats',
          description: 'Get detected threats from SentinelOne EDR',
          parameters: {
            severity: { type: 'string', description: 'Severity', enum: ['critical', 'high', 'medium', 'low'] },
            status: { type: 'string', description: 'Status', enum: ['active', 'mitigated', 'resolved'] },
          },
          execute: async (params) => connectors.sentinelone!.getThreats(params),
        }),

        this.createTool({
          name: 'quarantine_threat',
          description: 'Quarantine a threat to prevent spread - use for active malware',
          parameters: {
            threatId: { type: 'string', description: 'Threat ID to quarantine' },
          },
          required: ['threatId'],
          strict: true,
          execute: async (params) =>
            connectors.sentinelone!.quarantineThreat(params['threatId'] as string),
        }),
      )
    }

    // Jira tools
    if (connectors.jira) {
      tools.push(
        this.createTool({
          name: 'create_security_ticket',
          description: 'Create a Jira ticket for a security finding',
          parameters: {
            projectKey: { type: 'string', description: 'Jira project key' },
            title: { type: 'string', description: 'Ticket title' },
            description: { type: 'string', description: 'Detailed description' },
            severity: { type: 'string', description: 'Severity', enum: ['critical', 'high', 'medium', 'low'] },
            source: { type: 'string', description: 'Source connector' },
          },
          required: ['projectKey', 'title', 'description', 'severity', 'source'],
          strict: true,
          execute: async (params) => connectors.jira!.createSecurityTicket(
            params['projectKey'] as string,
            params['title'] as string,
            params['description'] as string,
            params['severity'] as string,
            params['source'] as string,
          ),
        }),
      )
    }

    return {
      name: 'SecurityAnalystAgent',
      instructions: `You are an expert cybersecurity analyst with access to enterprise security tools.
      
Your capabilities:
- Analyze vulnerabilities from Qualys vulnerability management
- Monitor threats and endpoints via SentinelOne EDR
- Create and manage security tickets in Jira
- Correlate findings across multiple security tools

Guidelines:
- Always prioritize critical and high severity findings
- When you find an active threat, recommend quarantine
- Create Jira tickets for findings that need remediation
- Provide clear, actionable security recommendations
- Format your analysis with severity, affected assets, and recommended actions`,
      tools,
      model: 'gpt-4o',
    }
  }

  // ============================================
  // Compliance Agent
  // ============================================

  static createComplianceAgent(connectors: {
    qualys?: {
      getComplianceControls: () => Promise<unknown>
      getVulnerabilities: (filter?: unknown) => Promise<unknown>
    }
    manageengine?: {
      getMissingPatches: () => Promise<unknown>
      getCriticalPatches: () => Promise<unknown>
    }
    jira?: {
      createSecurityTicket: (
        projectKey: string,
        title: string,
        description: string,
        severity: string,
        source: string,
      ) => Promise<unknown>
    }
  }): OpenAIAgentDefinition {
    const tools: OpenAIAgentTool[] = []

    if (connectors.qualys) {
      tools.push(
        this.createTool({
          name: 'get_compliance_controls',
          description: 'Get compliance control status from Qualys',
          execute: async () => connectors.qualys!.getComplianceControls(),
        }),
      )
    }

    if (connectors.manageengine) {
      tools.push(
        this.createTool({
          name: 'get_missing_patches',
          description: 'Get missing security patches from ManageEngine',
          execute: async () => connectors.manageengine!.getMissingPatches(),
        }),

        this.createTool({
          name: 'get_critical_patches',
          description: 'Get critical missing patches',
          execute: async () => connectors.manageengine!.getCriticalPatches(),
        }),
      )
    }

    if (connectors.jira) {
      tools.push(
        this.createTool({
          name: 'create_compliance_ticket',
          description: 'Create a compliance issue ticket in Jira',
          parameters: {
            projectKey: { type: 'string', description: 'Jira project key' },
            title: { type: 'string', description: 'Issue title' },
            description: { type: 'string', description: 'Description' },
            severity: { type: 'string', description: 'Severity', enum: ['critical', 'high', 'medium', 'low'] },
          },
          required: ['projectKey', 'title', 'description', 'severity'],
          execute: async (params) => connectors.jira!.createSecurityTicket(
            params['projectKey'] as string,
            params['title'] as string,
            params['description'] as string,
            params['severity'] as string,
            'compliance',
          ),
        }),
      )
    }

    return {
      name: 'ComplianceAgent',
      instructions: `You are a compliance officer AI assistant with access to security and patch management tools.

Your responsibilities:
- Review compliance control status
- Identify missing critical patches
- Create tickets for compliance violations
- Generate compliance reports
- Prioritize remediation by risk level

Always follow regulatory frameworks like ISO 27001, SOC2, and NIST when making recommendations.`,
      tools,
      model: 'gpt-4o',
    }
  }

  // ============================================
  // Format for OpenAI API
  // ============================================

  static toOpenAIFormat(tools: OpenAIAgentTool[]): Array<{
    type: 'function'
    function: OpenAIAgentTool['function']
  }> {
    return tools.map((tool) => ({
      type: tool.type,
      function: tool.function,
    }))
  }
}