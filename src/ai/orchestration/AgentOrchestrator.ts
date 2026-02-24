// ============================================
// AGENT ORCHESTRATOR - Complyment Connectors SDK
// ============================================
// Multi-agent orchestration - coordinate
// multiple AI agents working together
// ============================================

export type WorkflowStepType =
  | 'fetch'
  | 'analyze'
  | 'filter'
  | 'transform'
  | 'action'
  | 'notify'
  | 'condition'
  | 'parallel'

export type WorkflowStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled'

export interface WorkflowStep {
  id: string
  name: string
  type: WorkflowStepType
  connector?: string
  method?: string
  params?: Record<string, unknown>
  condition?: (context: WorkflowContext) => boolean
  transform?: (data: unknown, context: WorkflowContext) => unknown
  onSuccess?: (result: unknown, context: WorkflowContext) => void
  onError?: (error: Error, context: WorkflowContext) => void
  dependsOn?: string[]      // step IDs this step depends on
  retries?: number
  timeoutMs?: number
}

export interface WorkflowContext {
  workflowId: string
  results: Map<string, unknown>
  errors: Map<string, Error>
  startedAt: Date
  metadata: Record<string, unknown>
}

export interface WorkflowDefinition {
  id: string
  name: string
  description?: string
  steps: WorkflowStep[]
  onComplete?: (context: WorkflowContext) => void
  onError?: (error: Error, context: WorkflowContext) => void
}

export interface WorkflowExecution {
  executionId: string
  workflowId: string
  status: WorkflowStatus
  startedAt: Date
  completedAt?: Date
  context: WorkflowContext
  stepResults: Map<string, StepResult>
  error?: string
}

export interface StepResult {
  stepId: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped'
  startedAt?: Date
  completedAt?: Date
  data?: unknown
  error?: string
  retryCount: number
}

// ============================================
// Agent Orchestrator
// ============================================

export class AgentOrchestrator {
  private workflows: Map<string, WorkflowDefinition> = new Map()
  private executions: Map<string, WorkflowExecution> = new Map()
  private connectors: Map<string, Record<string, (...args: unknown[]) => Promise<unknown>>> = new Map()

  // ============================================
  // Register Connector
  // ============================================

  registerConnector(
    name: string,
    connector: Record<string, (...args: unknown[]) => Promise<unknown>>,
  ): void {
    this.connectors.set(name, connector)
  }

  // ============================================
  // Register Workflow
  // ============================================

  registerWorkflow(workflow: WorkflowDefinition): void {
    this.workflows.set(workflow.id, workflow)
  }

  // ============================================
  // Execute Workflow
  // ============================================

  async executeWorkflow(
    workflowId: string,
    metadata?: Record<string, unknown>,
  ): Promise<WorkflowExecution> {
    const workflow = this.workflows.get(workflowId)
    if (!workflow) throw new Error(`Workflow '${workflowId}' not found`)

    const executionId = this.generateId()
    const context: WorkflowContext = {
      workflowId,
      results: new Map(),
      errors: new Map(),
      startedAt: new Date(),
      metadata: metadata ?? {},
    }

    const execution: WorkflowExecution = {
      executionId,
      workflowId,
      status: 'running',
      startedAt: new Date(),
      context,
      stepResults: new Map(
        workflow.steps.map((s) => [
          s.id,
          { stepId: s.id, status: 'pending', retryCount: 0 },
        ]),
      ),
    }

    this.executions.set(executionId, execution)

    try {
      await this.executeSteps(workflow.steps, execution)
      execution.status = 'completed'
      execution.completedAt = new Date()
      workflow.onComplete?.(context)
    } catch (error) {
      execution.status = 'failed'
      execution.completedAt = new Date()
      execution.error = error instanceof Error ? error.message : 'Workflow failed'
      workflow.onError?.(
        error instanceof Error ? error : new Error(String(error)),
        context,
      )
    }

    return execution
  }

  // ============================================
  // Execute Steps (with dependency resolution)
  // ============================================

  private async executeSteps(
    steps: WorkflowStep[],
    execution: WorkflowExecution,
  ): Promise<void> {
    const completed = new Set<string>()
    const remaining = [...steps]

    while (remaining.length > 0) {
      // Find steps ready to execute (dependencies met)
      const ready = remaining.filter((step) => {
        if (!step.dependsOn?.length) return true
        return step.dependsOn.every((dep) => completed.has(dep))
      })

      if (ready.length === 0) {
        throw new Error('Circular dependency detected in workflow steps')
      }

      // Execute ready steps in parallel
      await Promise.all(
        ready.map(async (step) => {
          await this.executeStep(step, execution)
          completed.add(step.id)
          remaining.splice(remaining.indexOf(step), 1)
        }),
      )
    }
  }

  // ============================================
  // Execute Single Step
  // ============================================

  private async executeStep(
    step: WorkflowStep,
    execution: WorkflowExecution,
  ): Promise<void> {
    const stepResult = execution.stepResults.get(step.id)!
    const { context } = execution

    // Check condition
    if (step.condition && !step.condition(context)) {
      stepResult.status = 'skipped'
      return
    }

    stepResult.status = 'running'
    stepResult.startedAt = new Date()

    const maxRetries = step.retries ?? 0
    let lastError: Error | undefined

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      try {
        let result: unknown

        if (step.type === 'fetch' || step.type === 'action') {
          result = await this.executeConnectorStep(step, context)
        } else if (step.type === 'transform' && step.transform) {
          const prevResult = context.results.get(step.dependsOn?.[0] ?? '')
          result = step.transform(prevResult, context)
        } else if (step.type === 'filter') {
          result = await this.executeFilterStep(step, context)
        } else if (step.type === 'parallel') {
          result = await this.executeParallelStep(step, context)
        }

        // Store result
        context.results.set(step.id, result)
        stepResult.data = result
        stepResult.status = 'completed'
        stepResult.completedAt = new Date()

        step.onSuccess?.(result, context)
        return

      } catch (error) {
        lastError = error instanceof Error ? error : new Error(String(error))
        stepResult.retryCount = attempt

        if (attempt < maxRetries) {
          await this.sleep(Math.pow(2, attempt) * 1000)
        }
      }
    }

    // All retries failed
    stepResult.status = 'failed'
    stepResult.error = lastError?.message
    stepResult.completedAt = new Date()
    context.errors.set(step.id, lastError!)
    step.onError?.(lastError!, context)

    throw lastError
  }

  // ============================================
  // Execute Connector Step
  // ============================================

  private async executeConnectorStep(
    step: WorkflowStep,
    context: WorkflowContext,
  ): Promise<unknown> {
    if (!step.connector || !step.method) {
      throw new Error(`Step '${step.id}' missing connector or method`)
    }

    const connector = this.connectors.get(step.connector)
    if (!connector) {
      throw new Error(`Connector '${step.connector}' not registered`)
    }

    const method = connector[step.method]
    if (!method) {
      throw new Error(`Method '${step.method}' not found on connector '${step.connector}'`)
    }

    // Resolve params - can reference previous step results
    const resolvedParams = this.resolveParams(step.params ?? {}, context)
    return method(resolvedParams)
  }

  // ============================================
  // Execute Filter Step
  // ============================================

  private async executeFilterStep(
    step: WorkflowStep,
    context: WorkflowContext,
  ): Promise<unknown> {
    const sourceStepId = step.dependsOn?.[0]
    if (!sourceStepId) return []

    const sourceData = context.results.get(sourceStepId)
    if (!Array.isArray(sourceData)) return sourceData

    if (!step.condition) return sourceData
    return sourceData.filter((item) =>
      step.condition!({ ...context, results: new Map([['current', item]]) }),
    )
  }

  // ============================================
  // Execute Parallel Step
  // ============================================

  private async executeParallelStep(
    step: WorkflowStep,
    context: WorkflowContext,
  ): Promise<unknown[]> {
    if (!step.params?.['steps']) return []

    const parallelSteps = step.params['steps'] as WorkflowStep[]
    return Promise.all(
      parallelSteps.map(async (s) => {
        const result = await this.executeConnectorStep(s, context)
        return result
      }),
    )
  }

  // ============================================
  // Resolve Params (support ${stepId.field} syntax)
  // ============================================

  private resolveParams(
    params: Record<string, unknown>,
    context: WorkflowContext,
  ): Record<string, unknown> {
    const resolved: Record<string, unknown> = {}

    for (const [key, value] of Object.entries(params)) {
      if (typeof value === 'string' && value.startsWith('${')) {
        const match = value.match(/^\$\{(.+?)(?:\.(.+))?\}$/)
        if (match) {
          const stepId = match[1]
          const field = match[2]
          const stepResult = context.results.get(stepId)

          resolved[key] = field
            ? (stepResult as Record<string, unknown>)?.[field]
            : stepResult
        } else {
          resolved[key] = value
        }
      } else {
        resolved[key] = value
      }
    }

    return resolved
  }

  // ============================================
  // Pre-built Security Workflows
  // ============================================

  createVulnerabilityResponseWorkflow(): WorkflowDefinition {
    return {
      id: 'vulnerability-response',
      name: 'Automated Vulnerability Response',
      description: 'Fetch critical vulns → Create Jira tickets → Notify team',
      steps: [
        {
          id: 'fetch-vulns',
          name: 'Fetch Critical Vulnerabilities',
          type: 'fetch',
          connector: 'qualys',
          method: 'getCriticalVulnerabilities',
        },
        {
          id: 'fetch-threats',
          name: 'Fetch Active Threats',
          type: 'fetch',
          connector: 'sentinelone',
          method: 'getCriticalThreats',
        },
        {
          id: 'create-tickets',
          name: 'Create Jira Tickets',
          type: 'action',
          connector: 'jira',
          method: 'createSecurityTicket',
          dependsOn: ['fetch-vulns', 'fetch-threats'],
          params: {
            projectKey: 'SEC',
            title: 'Critical Security Finding',
            description: '${fetch-vulns}',
            severity: 'critical',
            source: 'automated-workflow',
          },
        },
      ],
    }
  }

  createThreatResponseWorkflow(): WorkflowDefinition {
    return {
      id: 'threat-response',
      name: 'Automated Threat Response',
      description: 'Detect threats → Quarantine → Create ticket',
      steps: [
        {
          id: 'fetch-threats',
          name: 'Fetch Active Threats',
          type: 'fetch',
          connector: 'sentinelone',
          method: 'getCriticalThreats',
        },
        {
          id: 'quarantine',
          name: 'Quarantine Threats',
          type: 'action',
          connector: 'sentinelone',
          method: 'quarantineThreat',
          dependsOn: ['fetch-threats'],
          params: { threatId: '${fetch-threats.id}' },
        },
        {
          id: 'create-ticket',
          name: 'Create Jira Ticket',
          type: 'action',
          connector: 'jira',
          method: 'createSecurityTicket',
          dependsOn: ['quarantine'],
          params: {
            projectKey: 'SEC',
            title: 'Threat Quarantined',
            description: '${fetch-threats}',
            severity: 'critical',
            source: 'sentinelone',
          },
        },
      ],
    }
  }

  // ============================================
  // Query Executions
  // ============================================

  getExecution(executionId: string): WorkflowExecution | undefined {
    return this.executions.get(executionId)
  }

  getExecutionsByWorkflow(workflowId: string): WorkflowExecution[] {
    return Array.from(this.executions.values()).filter(
      (e) => e.workflowId === workflowId,
    )
  }

  getStats() {
    const all = Array.from(this.executions.values())
    return {
      totalExecutions: all.length,
      completed: all.filter((e) => e.status === 'completed').length,
      failed: all.filter((e) => e.status === 'failed').length,
      running: all.filter((e) => e.status === 'running').length,
      registeredWorkflows: this.workflows.size,
      registeredConnectors: this.connectors.size,
    }
  }

  // ============================================
  // Utility
  // ============================================

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms))
  }

  private generateId(): string {
    return `exec_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`
  }
}

// ============================================
// Global Orchestrator
// ============================================

export const orchestrator = new AgentOrchestrator()