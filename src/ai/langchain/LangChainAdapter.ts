// ============================================
// LANGCHAIN ADAPTER - Skillmine Connectors SDK
// ============================================
// Convert connectors to LangChain Tools
// so AI agents can use them directly
// ============================================

export interface LangChainToolSchema {
    name: string
    description: string
    schema: {
        type: 'object'
        properties: Record<string, {
            type: string
            description: string
            enum?: string[]
        }>
        required?: string[]
    }
}

export interface LangChainTool {
    name: string
    description: string
    schema: LangChainToolSchema['schema']
    call: (input: string | Record<string, unknown>) => Promise<string>
}

// ============================================
// LangChain Adapter
// ============================================

export class LangChainAdapter {

    // ============================================
    // Create Tool from Connector Method
    // ============================================

    static createTool(options: {
        name: string
        description: string
        schema?: LangChainToolSchema['schema']
        handler: (input: Record<string, unknown>) => Promise<unknown>
    }): LangChainTool {
        return {
            name: options.name,
            description: options.description,
            schema: options.schema ?? { type: 'object', properties: {} },
            call: async (input) => {
                try {
                    const parsedInput = typeof input === 'string'
                        ? JSON.parse(input)
                        : input

                    const result = await options.handler(parsedInput)
                    return JSON.stringify(result, null, 2)
                } catch (error) {
                    return JSON.stringify({
                        error: error instanceof Error ? error.message : 'Tool execution failed',
                    })
                }
            },
        }
    }

    // ============================================
    // Qualys Tools
    // ============================================

    static createQualysTools(qualysConnector: {
        getAssets: (filter?: unknown) => Promise<unknown>
        getVulnerabilities: (filter?: unknown) => Promise<unknown>
        getCriticalVulnerabilities: () => Promise<unknown>
        getNormalizedVulnerabilities: (filter?: unknown) => Promise<unknown>
        healthCheck: () => Promise<unknown>
    }): LangChainTool[] {
        return [
            this.createTool({
                name: 'qualys_get_assets',
                description: 'Fetch all IT assets and hosts from Qualys. Use this to get information about servers, workstations, and network devices.',
                schema: {
                    type: 'object',
                    properties: {
                        hostname: { type: 'string', description: 'Filter by hostname' },
                        ipAddress: { type: 'string', description: 'Filter by IP address' },
                        limit: { type: 'number', description: 'Max results to return' },
                    },
                },
                handler: async (input) => qualysConnector.getAssets(input),
            }),

            this.createTool({
                name: 'qualys_get_vulnerabilities',
                description: 'Get vulnerability scan results from Qualys. Returns CVEs, severity, affected hosts.',
                schema: {
                    type: 'object',
                    properties: {
                        severity: {
                            type: 'array',
                            description: 'Severity levels to filter (1=Info, 2=Low, 3=Medium, 4=High, 5=Critical)',
                        },
                        status: {
                            type: 'string',
                            description: 'Status filter',
                            enum: ['Active', 'Fixed', 'New', 'Re-Opened'],
                        },
                    },
                },
                handler: async (input) => qualysConnector.getVulnerabilities(input),
            }),

            this.createTool({
                name: 'qualys_get_critical_vulnerabilities',
                description: 'Get only critical and high severity active vulnerabilities from Qualys. Use this for urgent security assessment.',
                handler: async () => qualysConnector.getCriticalVulnerabilities(),
            }),

            this.createTool({
                name: 'qualys_normalized_vulnerabilities',
                description: 'Get vulnerabilities in normalized format for cross-connector comparison.',
                handler: async (input) => qualysConnector.getNormalizedVulnerabilities(input),
            }),

            this.createTool({
                name: 'qualys_health_check',
                description: 'Check if Qualys connector is healthy and connected.',
                handler: async () => qualysConnector.healthCheck(),
            }),
        ]
    }

    // ============================================
    // SentinelOne Tools
    // ============================================

    static createSentinelOneTools(s1Connector: {
        getAgents: (filter?: unknown) => Promise<unknown>
        getThreats: (filter?: unknown) => Promise<unknown>
        getCriticalThreats: () => Promise<unknown>
        getActiveThreatCount: () => Promise<unknown>
        quarantineThreat: (id: string) => Promise<unknown>
        killThreat: (id: string) => Promise<unknown>
        getNormalizedThreats: (filter?: unknown) => Promise<unknown>
        healthCheck: () => Promise<unknown>
    }): LangChainTool[] {
        return [
            this.createTool({
                name: 'sentinelone_get_agents',
                description: 'Get all endpoint agents from SentinelOne EDR. Returns device info, status, and threat count.',
                schema: {
                    type: 'object',
                    properties: {
                        infected: { type: 'boolean', description: 'Return only infected agents' },
                        limit: { type: 'number', description: 'Max results' },
                    },
                },
                handler: async (input) => s1Connector.getAgents(input),
            }),

            this.createTool({
                name: 'sentinelone_get_threats',
                description: 'Get detected threats from SentinelOne. Returns malware, ransomware, and suspicious activity.',
                schema: {
                    type: 'object',
                    properties: {
                        severity: {
                            type: 'string',
                            description: 'Severity filter',
                            enum: ['critical', 'high', 'medium', 'low'],
                        },
                        status: {
                            type: 'string',
                            description: 'Status filter',
                            enum: ['active', 'mitigated', 'resolved', 'suspicious'],
                        },
                    },
                },
                handler: async (input) => s1Connector.getThreats(input),
            }),

            this.createTool({
                name: 'sentinelone_get_critical_threats',
                description: 'Get only critical and high severity active threats from SentinelOne.',
                handler: async () => s1Connector.getCriticalThreats(),
            }),

            this.createTool({
                name: 'sentinelone_quarantine_threat',
                description: 'Quarantine a specific threat to prevent spread. Requires threat ID.',
                schema: {
                    type: 'object',
                    properties: {
                        threatId: { type: 'string', description: 'The threat ID to quarantine' },
                    },
                    required: ['threatId'],
                },
                handler: async (input) =>
                    s1Connector.quarantineThreat(input['threatId'] as string),
            }),

            this.createTool({
                name: 'sentinelone_kill_threat',
                description: 'Kill a threat process immediately. Use for active malware.',
                schema: {
                    type: 'object',
                    properties: {
                        threatId: { type: 'string', description: 'The threat ID to kill' },
                    },
                    required: ['threatId'],
                },
                handler: async (input) =>
                    s1Connector.killThreat(input['threatId'] as string),
            }),

            this.createTool({
                name: 'sentinelone_health_check',
                description: 'Check SentinelOne connector health.',
                handler: async () => s1Connector.healthCheck(),
            }),
        ]
    }

    // ============================================
    // Jira Tools
    // ============================================

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
    }): LangChainTool[] {
        return [
            this.createTool({
                name: 'jira_get_issues',
                description: 'Get issues from Jira project management. Filter by project, status, priority.',
                schema: {
                    type: 'object',
                    properties: {
                        projectKey: { type: 'string', description: 'Jira project key e.g. SEC, DEV' },
                        status: { type: 'string', description: 'Issue status filter' },
                        priority: { type: 'string', description: 'Priority filter' },
                        jql: { type: 'string', description: 'Custom JQL query' },
                    },
                },
                handler: async (input) => jiraConnector.getIssues(input),
            }),

            this.createTool({
                name: 'jira_create_issue',
                description: 'Create a new Jira issue.',
                schema: {
                    type: 'object',
                    properties: {
                        projectKey: { type: 'string', description: 'Jira project key' },
                        summary: { type: 'string', description: 'Issue summary' },
                        description: { type: 'string', description: 'Issue description' },
                        issueType: { type: 'string', description: 'Issue type (e.g., Bug, Task)' },
                    },
                    required: ['projectKey', 'summary', 'issueType'],
                },
                handler: async (input) => jiraConnector.createIssue(input),
            }),

            this.createTool({
                name: 'jira_update_issue',
                description: 'Update an existing Jira issue.',
                schema: {
                    type: 'object',
                    properties: {
                        issueKey: { type: 'string', description: 'The issue key (e.g., SEC-123)' },
                        summary: { type: 'string', description: 'Updated summary' },
                        priority: { type: 'string', description: 'Updated priority' },
                    },
                    required: ['issueKey'],
                },
                handler: async (input) => {
                    const { issueKey, ...rest } = input
                    return jiraConnector.updateIssue(issueKey as string, rest)
                },
            }),

            this.createTool({
                name: 'jira_create_security_ticket',
                description: 'Create a security ticket in Jira from a vulnerability or threat finding.',
                schema: {
                    type: 'object',
                    properties: {
                        projectKey: { type: 'string', description: 'Jira project key' },
                        title: { type: 'string', description: 'Issue title/summary' },
                        description: { type: 'string', description: 'Detailed description' },
                        severity: {
                            type: 'string',
                            description: 'Severity level',
                            enum: ['critical', 'high', 'medium', 'low'],
                        },
                        source: { type: 'string', description: 'Source connector (qualys, sentinelone etc)' },
                    },
                    required: ['projectKey', 'title', 'description', 'severity', 'source'],
                },
                handler: async (input) => jiraConnector.createSecurityTicket(
                    input['projectKey'] as string,
                    input['title'] as string,
                    input['description'] as string,
                    input['severity'] as string,
                    input['source'] as string,
                ),
            }),

            this.createTool({
                name: 'jira_add_comment',
                description: 'Add a comment to an existing Jira issue.',
                schema: {
                    type: 'object',
                    properties: {
                        issueKey: { type: 'string', description: 'Issue key e.g. SEC-123' },
                        comment: { type: 'string', description: 'Comment text to add' },
                    },
                    required: ['issueKey', 'comment'],
                },
                handler: async (input) => jiraConnector.addComment(
                    input['issueKey'] as string,
                    input['comment'] as string,
                ),
            }),

            this.createTool({
                name: 'jira_transition_issue',
                description: 'Change the status of a Jira issue.',
                schema: {
                    type: 'object',
                    properties: {
                        issueKey: { type: 'string', description: 'Issue key e.g. SEC-123' },
                        transitionId: { type: 'string', description: 'Transition ID to apply' },
                    },
                    required: ['issueKey', 'transitionId'],
                },
                handler: async (input) => jiraConnector.transitionIssue(
                    input['issueKey'] as string,
                    input['transitionId'] as string,
                ),
            }),

            this.createTool({
                name: 'jira_health_check',
                description: 'Check Jira connector health.',
                handler: async () => jiraConnector.healthCheck(),
            }),
        ]
    }

    // ============================================
    // Create All Tools (Full Toolkit)
    // ============================================

    static createAllTools(connectors: {
        qualys?: Parameters<typeof LangChainAdapter.createQualysTools>[0]
        sentinelone?: Parameters<typeof LangChainAdapter.createSentinelOneTools>[0]
        jira?: Parameters<typeof LangChainAdapter.createJiraTools>[0]
    }): LangChainTool[] {
        const tools: LangChainTool[] = []

        if (connectors.qualys) {
            tools.push(...this.createQualysTools(connectors.qualys))
        }
        if (connectors.sentinelone) {
            tools.push(...this.createSentinelOneTools(connectors.sentinelone))
        }
        if (connectors.jira) {
            tools.push(...this.createJiraTools(connectors.jira))
        }

        return tools
    }
}