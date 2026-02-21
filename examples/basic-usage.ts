// ============================================
// BASIC USAGE - Skillmine Connectors SDK
// ============================================

import {
    QualysConnector,
    SentinelOneConnector,
    JiraConnector,
    registry,
    auditLogger,
    tracer,
    normalizationEngine,
    semanticSearch,
    LangChainAdapter,
    VercelAIAdapter,
    MCPServer,
    HITLManager,
    AgentWorkflow,
    envHandler,
    SDK_VERSION,
} from '../src'

console.log(`@skillmine/connectors-sdk v${SDK_VERSION}`)

// ============================================
// 1. Setup Connectors
// ============================================

const qualys = new QualysConnector({
    baseUrl: 'https://qualysapi.qualys.com',
    username: process.env.QUALYS_USERNAME ?? 'demo',
    password: process.env.QUALYS_PASSWORD ?? 'demo',
})

const sentinelone = new SentinelOneConnector({
    baseUrl: 'https://your-instance.sentinelone.net',
    apiToken: process.env.S1_API_TOKEN ?? 'demo',
})

const jira = new JiraConnector({
    baseUrl: 'https://your-org.atlassian.net',
    email: process.env.JIRA_EMAIL ?? 'demo@example.com',
    apiToken: process.env.JIRA_API_TOKEN ?? 'demo',
})

// ============================================
// 2. Register in Global Registry
// ============================================

registry.register('qualys', qualys)
registry.register('sentinelone', sentinelone)
registry.register('jira', jira)

console.log('Registered connectors:', registry.list())

// ============================================
// 3. Tracing Example
// ============================================

async function tracedFetch() {
    const spanId = tracer.startSpan({
        name: 'fetch-vulnerabilities',
        connector: 'qualys',
        method: 'GET',
    })

    try {
        // Simulated fetch
        tracer.addEvent(spanId, 'cache.miss')
        tracer.setAttribute(spanId, 'result.count', 42)
        tracer.endSpan(spanId)
        console.log('Span completed')
    } catch (error) {
        tracer.endSpan(spanId, error as Error)
    }
}

// ============================================
// 4. Audit Logging Example
// ============================================

function auditExample() {
    auditLogger.logSuccess('data.fetch', 'qualys', {
        resourceType: 'vulnerabilities',
        count: 42,
    }, 320)

    auditLogger.logFailure('auth.login', 'sentinelone', 'Invalid API token')

    console.log('Audit stats:', auditLogger.getStats())
    console.log('Recent entries:', auditLogger.getRecentEntries(3))
}

// ============================================
// 5. Normalization Example
// ============================================

function normalizationExample() {
    const qualysVulns = [
        {
            id: 'vuln-001',
            title: 'OpenSSL Critical CVE',
            severity: 'critical' as const,
            cve: 'CVE-2024-1234',
            affectedAsset: '192.168.1.10',
            source: 'qualys',
            detectedAt: new Date(),
        },
    ]

    const s1Threats = [
        {
            id: 'threat-001',
            title: 'Ransomware Detected',
            severity: 'critical' as const,
            cve: undefined,
            affectedAsset: 'DESKTOP-ABC123',
            source: 'sentinelone',
            detectedAt: new Date(),
        },
    ]

    // Normalize across connectors
    const result = normalizationEngine.normalizeVulnerabilities([
        {
            connector: 'qualys',
            data: qualysVulns,
            mapper: (item) => item as ReturnType<typeof normalizationEngine.normalizeVulnerabilities>['data'][0],
        },
        {
            connector: 'sentinelone',
            data: s1Threats,
            mapper: (item) => item as ReturnType<typeof normalizationEngine.normalizeVulnerabilities>['data'][0],
        },
    ])

    console.log('Normalized vulnerabilities:', result.total)
    console.log('Sources:', result.sources)

    const stats = normalizationEngine.getSeverityStats(result.data)
    console.log('Severity breakdown:', stats)
}

// ============================================
// 6. Semantic Search Example
// ============================================

async function semanticSearchExample() {
    // Index some data
    semanticSearch.indexVulnerabilities([
        {
            id: 'v1',
            title: 'Critical OpenSSL vulnerability',
            severity: 'critical',
            cve: 'CVE-2024-1234',
            affectedAsset: '192.168.1.10',
            source: 'qualys',
        },
        {
            id: 'v2',
            title: 'Apache Log4j Remote Code Execution',
            severity: 'critical',
            cve: 'CVE-2021-44228',
            affectedAsset: '10.0.0.5',
            source: 'qualys',
        },
    ])

    semanticSearch.indexThreats([
        {
            id: 't1',
            name: 'Ransomware detected on endpoint',
            severity: 'critical',
            affectedAsset: 'DESKTOP-XYZ',
            source: 'sentinelone',
        },
    ])

    // Natural language search
    const results = await semanticSearch.search('critical ransomware threat')
    console.log('Search results:', results.length)
    console.log('Top result:', results[0]?.document.content)
    console.log('Index stats:', semanticSearch.getStats())
}

// ============================================
// 7. LangChain Tools Example
// ============================================

function langchainExample() {
    const tools = LangChainAdapter.createAllTools({
        qualys: {
            getAssets: async () => ({ data: [] }),
            getVulnerabilities: async () => ({ data: [] }),
            getCriticalVulnerabilities: async () => ({ data: [] }),
            getNormalizedVulnerabilities: async () => ({ data: [] }),
            healthCheck: async () => ({ status: 'healthy' }),
        },
        jira: {
            getIssues: async () => ({ data: [] }),
            createIssue: async (request: unknown) => ({ id: 'issue-1', ...request as object }),
            createSecurityTicket: async (projectKey: string, title: string, description: string, severity: string, source: string) => ({ key: 'SEC-1', projectKey, title, description, severity, source }),
            addComment: async () => ({ id: 'comment-1' }),
            updateIssue: async (issueKey: string, request: unknown) => ({ success: true, issueKey, request }),
            transitionIssue: async (issueKey: string, transitionId: string) => ({ success: true, issueKey, transitionId }),
            healthCheck: async () => ({ status: 'healthy' }),
        },
    })

    console.log('LangChain tools created:', tools.map((t) => t.name))
}

// ============================================
// 8. Vercel AI Tools Example
// ============================================

function vercelAIExample() {
    const toolSet = VercelAIAdapter.createFullToolSet({
        qualys: {
            getAssets: async () => ({ data: [] }),
            getVulnerabilities: async () => ({ data: [] }),
            getCriticalVulnerabilities: async () => ({ data: [] }),
            getNormalizedVulnerabilities: async () => ({ data: [] }),
            getScans: async () => ({ data: [] }),
            healthCheck: async () => ({ status: 'healthy' }),
        },
    })

    console.log('Vercel AI tools:', Object.keys(toolSet))
}

// ============================================
// 9. MCP Server Example
// ============================================

function mcpExample() {
    const mcp = new MCPServer({
        name: 'skillmine-security-mcp',
        version: '1.0.0',
    })

    mcp.registerTool({
        name: 'get_security_summary',
        description: 'Get overall security posture summary',
        inputSchema: { type: 'object', properties: {} },
        handler: async () => ({
            content: [{
                type: 'json' as const,
                data: {
                    criticalVulns: 5,
                    activeThreats: 2,
                    infectedAgents: 1,
                    overallRisk: 'HIGH',
                },
            }],
        }),
    })

    console.log('MCP server info:', mcp.getServerInfo())
    console.log('MCP tools:', mcp.listTools().map((t) => t.name))
    console.log('MCP manifest:', JSON.stringify(mcp.generateManifest(), null, 2))
}

// ============================================
// 10. HITL Example
// ============================================

async function hitlExample() {
    const hitl = new HITLManager({
        autoApproveRiskLevels: ['low'],
        onApprovalRequired: (req) => {
            console.log(`⚠️  Approval needed: ${req.actionType} (Risk: ${req.riskLevel})`)
        },
        onCompleted: (req) => {
            console.log(`✅ Action completed: ${req.actionType}`)
        },
    })

    // Register handler
    hitl.registerHandler('scan.launch', async (params) => {
        console.log('Launching scan with params:', params)
        return { scanId: 'scan-123', status: 'running' }
    })

    // Low risk - auto approved
    const lowRiskRequest = await hitl.requestApproval({
        actionType: 'scan.launch',
        connector: 'qualys',
        description: 'Launch vulnerability scan on subnet',
        riskLevel: 'low',
        params: { subnet: '192.168.1.0/24' },
        requestedBy: 'SecurityAgent',
    })

    console.log('Low risk request status:', lowRiskRequest.status)
    console.log('HITL stats:', hitl.getStats())
}

// ============================================
// 11. Agent Workflow Example
// ============================================

async function workflowExample() {
    const workflow = new AgentWorkflow({
        requireApproval: false,
        agentName: 'DemoAgent',
    })

    // Mock connectors
    const mockQualys = {
        getCriticalVulnerabilities: async () => ({
            data: { data: [{ id: 'v1', title: 'Test Vuln', severity: 'critical' }] },
        }),
        getAssets: async () => ({ data: { data: [] } }),
        healthCheck: async () => ({ status: 'healthy' }),
    }

    const mockS1 = {
        getCriticalThreats: async () => ({
            data: { data: [], pagination: { totalItems: 0 } },
        }),
        getInfectedAgents: async () => ({ data: { data: [] } }),
        healthCheck: async () => ({ status: 'healthy' }),
    }

    const result = await workflow.runSecurityPostureAssessment({
        qualys: mockQualys,
        sentinelone: mockS1,
    })

    console.log('Workflow result:', result.workflowName)
    console.log('Status:', result.status)
    console.log('Steps:', result.steps.map((s) => `${s.name}: ${s.status}`))
    console.log('Summary:', result.summary)
}

// ============================================
// Run All Examples
// ============================================

async function main() {
    console.log('\n=== 1. Tracing ===')
    await tracedFetch()

    console.log('\n=== 2. Audit Logging ===')
    auditExample()

    console.log('\n=== 3. Normalization ===')
    normalizationExample()

    console.log('\n=== 4. Semantic Search ===')
    await semanticSearchExample()

    console.log('\n=== 5. LangChain Tools ===')
    langchainExample()

    console.log('\n=== 6. Vercel AI Tools ===')
    vercelAIExample()

    console.log('\n=== 7. MCP Server ===')
    mcpExample()

    console.log('\n=== 8. HITL Manager ===')
    await hitlExample()

    console.log('\n=== 9. Agent Workflow ===')
    await workflowExample()

    console.log('\n✅ All examples completed!')
}

main().catch(console.error)