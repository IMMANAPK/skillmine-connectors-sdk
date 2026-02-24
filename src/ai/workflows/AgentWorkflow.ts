// ============================================
// AGENT WORKFLOW - Complyment Connectors SDK
// ============================================
// Pre-built security workflows for AI agents
// Ready-to-use automation patterns
// ============================================

import { HITLManager, HITLActionType } from '../hitl/HITLManager'
import { AgentOrchestrator } from '../orchestration/AgentOrchestrator'
import { SemanticSearch } from '../semantic/SemanticSearch'
import { AuditLogger } from '../../audit/AuditLogger'

export type WorkflowTrigger =
    | 'manual'
    | 'scheduled'
    | 'threshold'
    | 'event'

export interface WorkflowTriggerConfig {
    type: WorkflowTrigger
    schedule?: string           // cron expression
    threshold?: {
        metric: string
        operator: '>' | '<' | '>=' | '<=' | '=='
        value: number
    }
    event?: string
}

export interface AgentWorkflowOptions {
    hitlManager?: HITLManager
    orchestrator?: AgentOrchestrator
    semanticSearch?: SemanticSearch
    auditLogger?: AuditLogger
    requireApproval?: boolean
    agentName?: string
}

export interface WorkflowResult {
    workflowName: string
    status: 'success' | 'failed' | 'pending_approval'
    startedAt: Date
    completedAt?: Date
    steps: Array<{
        name: string
        status: 'success' | 'failed' | 'skipped'
        data?: unknown
        error?: string
    }>
    summary?: string
    requiresAction?: string[]
}

// ============================================
// Agent Workflow
// ============================================

export class AgentWorkflow {
    private hitlManager?: HITLManager
    private orchestrator?: AgentOrchestrator
    private semanticSearch?: SemanticSearch
    private auditLogger?: AuditLogger
    private requireApproval: boolean
    private agentName: string

    constructor(options?: AgentWorkflowOptions) {
        this.hitlManager = options?.hitlManager
        this.orchestrator = options?.orchestrator
        this.semanticSearch = options?.semanticSearch
        this.auditLogger = options?.auditLogger
        this.requireApproval = options?.requireApproval ?? true
        this.agentName = options?.agentName ?? 'SecurityAgent'
    }

    // ============================================
    // Workflow 1: Security Posture Assessment
    // ============================================

    async runSecurityPostureAssessment(connectors: {
        qualys?: {
            getCriticalVulnerabilities: () => Promise<unknown>
            getAssets: () => Promise<unknown>
            healthCheck: () => Promise<unknown>
        }
        sentinelone?: {
            getCriticalThreats: () => Promise<unknown>
            getInfectedAgents: () => Promise<unknown>
            healthCheck: () => Promise<unknown>
        }
        checkpoint?: {
            getGateways: () => Promise<unknown>
            healthCheck: () => Promise<unknown>
        }
    }): Promise<WorkflowResult> {
        const result: WorkflowResult = {
            workflowName: 'Security Posture Assessment',
            status: 'success',
            startedAt: new Date(),
            steps: [],
            requiresAction: [],
        }

        // Step 1: Health checks
        const healthStep: WorkflowResult['steps'][number] = { name: 'Health Check', status: 'success', data: {} }
        try {
            const health: Record<string, unknown> = {}
            if (connectors.qualys) health['qualys'] = await connectors.qualys.healthCheck()
            if (connectors.sentinelone) health['sentinelone'] = await connectors.sentinelone.healthCheck()
            if (connectors.checkpoint) health['checkpoint'] = await connectors.checkpoint.healthCheck()
            healthStep.data = health
        } catch (error) {
            healthStep.status = 'failed'
        }
        result.steps.push(healthStep)

        // Step 2: Fetch critical vulnerabilities
        if (connectors.qualys) {
            const vulnStep: WorkflowResult['steps'][number] = { name: 'Fetch Critical Vulnerabilities', status: 'success', data: undefined as unknown }
            try {
                vulnStep.data = await connectors.qualys.getCriticalVulnerabilities()

                // Index for semantic search
                if (this.semanticSearch && vulnStep.data) {
                    const vulns = (vulnStep.data as { data?: { data?: unknown[] } })?.data?.data ?? []
                    this.semanticSearch.indexVulnerabilities(vulns as Parameters<SemanticSearch['indexVulnerabilities']>[0])
                }
            } catch (error) {
                vulnStep.status = 'failed'
            }
            result.steps.push(vulnStep)
        }

        // Step 3: Fetch active threats
        if (connectors.sentinelone) {
            const threatStep: WorkflowResult['steps'][number] = { name: 'Fetch Active Threats', status: 'success', data: undefined as unknown }
            try {
                threatStep.data = await connectors.sentinelone.getCriticalThreats()

                if (this.semanticSearch && threatStep.data) {
                    const threats = (threatStep.data as { data?: { data?: unknown[] } })?.data?.data ?? []
                    this.semanticSearch.indexThreats(threats as Parameters<SemanticSearch['indexThreats']>[0])
                }

                // Check if immediate action needed
                const threatCount = (threatStep.data as { data?: { pagination?: { totalItems?: number } } })
                    ?.data?.pagination?.totalItems ?? 0

                if (threatCount > 0) {
                    result.requiresAction?.push(`${threatCount} active threats require immediate attention`)
                }
            } catch (error) {
                threatStep.status = 'failed'
            }
            result.steps.push(threatStep)
        }

        // Step 4: Fetch infected agents
        if (connectors.sentinelone) {
            const agentStep: WorkflowResult['steps'][number] = { name: 'Fetch Infected Agents', status: 'success', data: undefined as unknown }
            try {
                agentStep.data = await connectors.sentinelone.getInfectedAgents()
            } catch (error) {
                agentStep.status = 'failed'
            }
            result.steps.push(agentStep)
        }

        result.completedAt = new Date()
        result.summary = this.generateAssessmentSummary(result)

        this.auditLogger?.logSuccess('data.fetch', 'workflow', {
            workflow: 'security-posture-assessment',
        })

        return result
    }

    // ============================================
    // Workflow 2: Automated Threat Response
    // ============================================

    async runThreatResponse(
        threatId: string,
        connectors: {
            sentinelone: {
                getThreats: (filter: unknown) => Promise<unknown>
                quarantineThreat: (id: string) => Promise<unknown>
                killThreat: (id: string) => Promise<unknown>
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
        },
        jiraProjectKey = 'SEC',
    ): Promise<WorkflowResult> {
        const result: WorkflowResult = {
            workflowName: 'Automated Threat Response',
            status: 'success',
            startedAt: new Date(),
            steps: [],
        }

        // Step 1: Get threat details
        const fetchStep: WorkflowResult['steps'][number] = { name: 'Fetch Threat Details', status: 'success', data: undefined as unknown }
        try {
            fetchStep.data = await connectors.sentinelone.getThreats({ ids: [threatId] })
        } catch (error) {
            fetchStep.status = 'failed'
            result.status = 'failed'
        }
        result.steps.push(fetchStep)

        if (result.status === 'failed') return result

        // Step 2: Request approval for quarantine (HITL)
        if (this.requireApproval && this.hitlManager) {
            const approvalStep: WorkflowResult['steps'][number] = { name: 'Request Quarantine Approval', status: 'success', data: undefined as unknown }
            try {
                const request = await this.hitlManager.requestApproval({
                    actionType: 'threat.quarantine' as HITLActionType,
                    connector: 'sentinelone',
                    description: `Quarantine threat ${threatId}`,
                    riskLevel: 'high',
                    params: { threatId },
                    requestedBy: this.agentName,
                })
                approvalStep.data = request

                if (request.status === 'pending') {
                    result.status = 'pending_approval'
                    result.steps.push(approvalStep)
                    return result
                }
            } catch (error) {
                approvalStep.status = 'failed'
            }
            result.steps.push(approvalStep)
        }

        // Step 3: Quarantine threat
        const quarantineStep: WorkflowResult['steps'][number] = { name: 'Quarantine Threat', status: 'success', data: undefined as unknown }
        try {
            quarantineStep.data = await connectors.sentinelone.quarantineThreat(threatId)
        } catch (error) {
            quarantineStep.status = 'failed'
            result.status = 'failed'
        }
        result.steps.push(quarantineStep)

        // Step 4: Create Jira ticket
        if (connectors.jira) {
            const ticketStep: WorkflowResult['steps'][number] = { name: 'Create Jira Ticket', status: 'success', data: undefined as unknown }
            try {
                ticketStep.data = await connectors.jira.createSecurityTicket(
                    jiraProjectKey,
                    `[SentinelOne] Threat Quarantined - ${threatId}`,
                    `Threat ${threatId} was automatically quarantined by ${this.agentName}`,
                    'critical',
                    'sentinelone',
                )
            } catch (error) {
                ticketStep.status = 'failed'
            }
            result.steps.push(ticketStep)
        }

        result.completedAt = new Date()
        this.auditLogger?.logSuccess('threat.mitigate', 'sentinelone', { threatId })

        return result
    }

    // ============================================
    // Workflow 3: Patch Compliance Check
    // ============================================

    async runPatchComplianceCheck(connectors: {
        manageengine: {
            getCriticalPatches: () => Promise<unknown>
            getMissingPatches: () => Promise<unknown>
            getComputers: () => Promise<unknown>
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
    }): Promise<WorkflowResult> {
        const result: WorkflowResult = {
            workflowName: 'Patch Compliance Check',
            status: 'success',
            startedAt: new Date(),
            steps: [],
            requiresAction: [],
        }

        // Step 1: Get critical missing patches
        const patchStep: WorkflowResult['steps'][number] = { name: 'Fetch Critical Missing Patches', status: 'success', data: undefined as unknown }
        try {
            patchStep.data = await connectors.manageengine.getCriticalPatches()
        } catch (error) {
            patchStep.status = 'failed'
        }
        result.steps.push(patchStep)

        // Step 2: Get affected computers
        const computerStep: WorkflowResult['steps'][number] = { name: 'Fetch Affected Computers', status: 'success', data: undefined as unknown }
        try {
            computerStep.data = await connectors.manageengine.getComputers()
        } catch (error) {
            computerStep.status = 'failed'
        }
        result.steps.push(computerStep)

        // Step 3: Create Jira ticket if critical patches missing
        if (connectors.jira && patchStep.data) {
            const ticketStep: WorkflowResult['steps'][number] = { name: 'Create Compliance Ticket', status: 'success', data: undefined as unknown }
            try {
                ticketStep.data = await connectors.jira.createSecurityTicket(
                    'SEC',
                    '[ManageEngine] Critical Patches Missing',
                    `Critical patches are missing on multiple systems. Immediate patching required.`,
                    'critical',
                    'manageengine',
                )
            } catch (error) {
                ticketStep.status = 'failed'
            }
            result.steps.push(ticketStep)
        }

        result.completedAt = new Date()
        result.summary = `Patch compliance check completed. Review results for action items.`

        return result
    }

    // ============================================
    // Workflow 4: Natural Language Security Query
    // ============================================

    async runNLQuery(
        query: string,
        options?: { topK?: number; type?: string },
    ): Promise<WorkflowResult> {
        const result: WorkflowResult = {
            workflowName: 'Natural Language Security Query',
            status: 'success',
            startedAt: new Date(),
            steps: [],
        }

        if (!this.semanticSearch) {
            result.status = 'failed'
            result.steps.push({
                name: 'Semantic Search',
                status: 'failed',
                error: 'SemanticSearch not configured',
            })
            return result
        }

        const searchStep: WorkflowResult['steps'][number] = { name: 'Semantic Search', status: 'success', data: undefined as unknown }
        try {
            searchStep.data = await this.semanticSearch.search(query, {
                topK: options?.topK ?? 10,
            })
        } catch (error) {
            searchStep.status = 'failed'
            result.status = 'failed'
        }
        result.steps.push(searchStep)

        result.completedAt = new Date()
        result.summary = `Found results for: "${query}"`

        return result
    }

    // ============================================
    // Summary Generator
    // ============================================

    private generateAssessmentSummary(result: WorkflowResult): string {
        const failed = result.steps.filter((s) => s.status === 'failed').length
        const success = result.steps.filter((s) => s.status === 'success').length
        const actions = result.requiresAction?.length ?? 0

        return `Security assessment completed: ${success} checks passed, ${failed} failed. ${actions > 0 ? `${actions} items require immediate action.` : 'No immediate action required.'}`
    }
}

// ============================================
// Global Agent Workflow
// ============================================

export const agentWorkflow = new AgentWorkflow({
    requireApproval: true,
    agentName: 'ComplymentSecurityAgent',
})