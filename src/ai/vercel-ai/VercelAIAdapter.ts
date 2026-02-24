// ============================================
// VERCEL AI ADAPTER - Complyment Connectors SDK
// ============================================
// Convert connectors to Vercel AI SDK Tools
// ============================================

export interface VercelAITool {
    description: string
    parameters: any
    execute: (args: any) => Promise<any>
}

export type VercelAIToolSet = Record<string, VercelAITool>

/**
 * Adapter for Vercel AI SDK (ai)
 */
export class VercelAIAdapter {
    /**
     * Create a tool for Vercel AI SDK
     */
    static createTool(options: {
        description: string
        parameters: any
        execute: (args: any) => Promise<any>
    }): VercelAITool {
        return {
            description: options.description,
            parameters: options.parameters,
            execute: options.execute,
        }
    }

    /**
     * Create a set of tools for a connector
     */
    static createToolkit(tools: VercelAIToolSet): VercelAIToolSet {
        return tools
    }

    /**
     * Create Qualys-specific tools for Vercel AI SDK
     */
    static createQualysTools(qualysConnector: {
        getAssets: (filter?: unknown) => Promise<unknown>
        getVulnerabilities: (filter?: unknown) => Promise<unknown>
        getCriticalVulnerabilities: () => Promise<unknown>
        getNormalizedVulnerabilities: (filter?: unknown) => Promise<unknown>
        getScans: (filter?: unknown) => Promise<unknown>
        healthCheck: () => Promise<unknown>
    }): VercelAIToolSet {
        return {
            qualys_get_assets: this.createTool({
                description: 'Fetch all IT assets and hosts from Qualys.',
                parameters: {
                    type: 'object',
                    properties: {
                        hostname: { type: 'string' },
                        ipAddress: { type: 'string' },
                    },
                },
                execute: async (args) => qualysConnector.getAssets(args),
            }),
            qualys_get_vulnerabilities: this.createTool({
                description: 'Get vulnerability scan results from Qualys.',
                parameters: {
                    type: 'object',
                    properties: {
                        severity: { type: 'array', items: { type: 'number' } },
                        status: { type: 'string' },
                    },
                },
                execute: async (args) => qualysConnector.getVulnerabilities(args),
            }),
            qualys_get_critical_vulnerabilities: this.createTool({
                description: 'Get critical and high severity active vulnerabilities from Qualys.',
                parameters: { type: 'object', properties: {} },
                execute: async () => qualysConnector.getCriticalVulnerabilities(),
            }),
            qualys_get_scans: this.createTool({
                description: 'Get vulnerability scan history and status from Qualys.',
                parameters: { type: 'object', properties: {} },
                execute: async (args) => qualysConnector.getScans(args),
            }),
            qualys_health_check: this.createTool({
                description: 'Check Qualys connector health.',
                parameters: { type: 'object', properties: {} },
                execute: async () => qualysConnector.healthCheck(),
            }),
        }
    }

    /**
     * Create SentinelOne-specific tools for Vercel AI SDK
     */
    static createSentinelOneTools(s1Connector: {
        getAgents: (filter?: unknown) => Promise<unknown>
        getThreats: (filter?: unknown) => Promise<unknown>
        getCriticalThreats: () => Promise<unknown>
        quarantineThreat: (id: string) => Promise<unknown>
        healthCheck: () => Promise<unknown>
    }): VercelAIToolSet {
        return {
            sentinelone_get_agents: this.createTool({
                description: 'Get all endpoint agents from SentinelOne.',
                parameters: {
                    type: 'object',
                    properties: {
                        infected: { type: 'boolean' },
                    },
                },
                execute: async (args) => s1Connector.getAgents(args),
            }),
            sentinelone_get_threats: this.createTool({
                description: 'Get detected threats from SentinelOne.',
                parameters: {
                    type: 'object',
                    properties: {
                        severity: { type: 'string' },
                        status: { type: 'string' },
                    },
                },
                execute: async (args) => s1Connector.getThreats(args),
            }),
            sentinelone_quarantine_threat: this.createTool({
                description: 'Quarantine a threat in SentinelOne.',
                parameters: {
                    type: 'object',
                    properties: {
                        threatId: { type: 'string' },
                    },
                    required: ['threatId'],
                },
                execute: async (args) => s1Connector.quarantineThreat(args.threatId),
            }),
            sentinelone_health_check: this.createTool({
                description: 'Check SentinelOne connector health.',
                parameters: { type: 'object', properties: {} },
                execute: async () => s1Connector.healthCheck(),
            }),
        }
    }

    /**
     * Create Jira-specific tools for Vercel AI SDK
     */
    static createJiraTools(jiraConnector: {
        getIssues: (filter?: unknown) => Promise<unknown>
        createIssue: (request: unknown) => Promise<unknown>
        createSecurityTicket: (
            projectKey: string,
            title: string,
            description: string,
            severity: string,
            source: string,
        ) => Promise<unknown>
        updateIssue: (issueKey: string, request: unknown) => Promise<unknown>
        addComment: (issueKey: string, body: string) => Promise<unknown>
        transitionIssue: (issueKey: string, transitionId: string) => Promise<unknown>
        healthCheck: () => Promise<unknown>
    }): VercelAIToolSet {
        return {
            jira_get_issues: this.createTool({
                description: 'Get issues from Jira.',
                parameters: {
                    type: 'object',
                    properties: {
                        projectKey: { type: 'string' },
                        status: { type: 'string' },
                    },
                },
                execute: async (args) => jiraConnector.getIssues(args),
            }),
            jira_create_issue: this.createTool({
                description: 'Create a new Jira issue.',
                parameters: {
                    type: 'object',
                    properties: {
                        projectKey: { type: 'string' },
                        summary: { type: 'string' },
                        issueType: { type: 'string' },
                    },
                    required: ['projectKey', 'summary', 'issueType'],
                },
                execute: async (args) => jiraConnector.createIssue(args),
            }),
            jira_update_issue: this.createTool({
                description: 'Update an existing Jira issue.',
                parameters: {
                    type: 'object',
                    properties: {
                        issueKey: { type: 'string' },
                        summary: { type: 'string' },
                    },
                    required: ['issueKey'],
                },
                execute: async (args) => {
                    const { issueKey, ...rest } = args
                    return jiraConnector.updateIssue(issueKey, rest)
                },
            }),
            jira_add_comment: this.createTool({
                description: 'Add a comment to a Jira issue.',
                parameters: {
                    type: 'object',
                    properties: {
                        issueKey: { type: 'string' },
                        comment: { type: 'string' },
                    },
                    required: ['issueKey', 'comment'],
                },
                execute: async (args) => jiraConnector.addComment(args.issueKey, args.comment),
            }),
            jira_health_check: this.createTool({
                description: 'Check Jira connector health.',
                parameters: { type: 'object', properties: {} },
                execute: async () => jiraConnector.healthCheck(),
            }),
        }
    }

    /**
     * Create a full set of tools from multiple connectors
     */
    static createFullToolSet(connectors: {
        qualys?: Parameters<typeof VercelAIAdapter.createQualysTools>[0]
        sentinelone?: Parameters<typeof VercelAIAdapter.createSentinelOneTools>[0]
        jira?: Parameters<typeof VercelAIAdapter.createJiraTools>[0]
    }): VercelAIToolSet {
        let toolSet: VercelAIToolSet = {}

        if (connectors.qualys) {
            toolSet = { ...toolSet, ...this.createQualysTools(connectors.qualys) }
        }
        if (connectors.sentinelone) {
            toolSet = { ...toolSet, ...this.createSentinelOneTools(connectors.sentinelone) }
        }
        if (connectors.jira) {
            toolSet = { ...toolSet, ...this.createJiraTools(connectors.jira) }
        }

        return toolSet
    }
}