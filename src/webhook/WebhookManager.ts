// ============================================
// WEBHOOK MANAGER - Skillmine Connectors SDK
// ============================================
// Receive and process webhook events from
// security tools (SentinelOne, Qualys, etc.)
// ============================================

import { EventEmitter } from 'events'
import crypto from 'crypto'

export type WebhookEventType =
    | 'threat.detected'
    | 'threat.resolved'
    | 'vulnerability.found'
    | 'vulnerability.fixed'
    | 'scan.completed'
    | 'agent.offline'
    | 'agent.online'
    | 'policy.changed'
    | 'patch.missing'
    | 'patch.installed'

export interface WebhookEvent {
    id: string
    type: WebhookEventType
    connector: string
    timestamp: Date
    payload: Record<string, unknown>
    signature?: string
}

export interface WebhookHandler {
    eventType: WebhookEventType | '*'
    connector?: string
    handler: (event: WebhookEvent) => void | Promise<void>
}

export interface WebhookEndpoint {
    id: string
    connector: string
    secret?: string
    enabled: boolean
    events: WebhookEventType[]
    receivedCount: number
    lastReceivedAt?: Date
}

// ============================================
// Webhook Manager
// ============================================

export class WebhookManager extends EventEmitter {
    private handlers: WebhookHandler[] = []
    private endpoints: Map<string, WebhookEndpoint> = new Map()
    private eventHistory: WebhookEvent[] = []
    private readonly maxHistory: number

    constructor(options?: { maxHistory?: number }) {
        super()
        this.maxHistory = options?.maxHistory ?? 1000
    }

    // ============================================
    // Register Endpoint
    // ============================================

    registerEndpoint(config: Omit<WebhookEndpoint, 'receivedCount'>): void {
        this.endpoints.set(config.id, {
            ...config,
            receivedCount: 0,
        })
    }

    // ============================================
    // Register Handler
    // ============================================

    on(eventType: WebhookEventType | '*', handler: (event: WebhookEvent) => void): this
    on(event: string | symbol, listener: (...args: any[]) => void): this
    on(event: string | symbol, listener: (...args: any[]) => void): this {
        if (
            typeof event === 'string' &&
            (event === '*' || event.includes('.'))
        ) {
            this.handlers.push({
                eventType: event as WebhookEventType | '*',
                handler: listener as (event: WebhookEvent) => void,
            })
        }
        return super.on(event, listener)
    }

    onConnector(
        connector: string,
        eventType: WebhookEventType | '*',
        handler: (event: WebhookEvent) => void | Promise<void>,
    ): void {
        this.handlers.push({ eventType, connector, handler })
    }

    // ============================================
    // Process Incoming Webhook
    // ============================================

    async processWebhook(
        endpointId: string,
        payload: Record<string, unknown>,
        signature?: string,
    ): Promise<{ success: boolean; error?: string }> {
        const endpoint = this.endpoints.get(endpointId)

        if (!endpoint) {
            return { success: false, error: `Endpoint '${endpointId}' not found` }
        }

        if (!endpoint.enabled) {
            return { success: false, error: 'Endpoint is disabled' }
        }

        // Verify signature if secret configured
        if (endpoint.secret && signature) {
            const isValid = this.verifySignature(
                JSON.stringify(payload),
                signature,
                endpoint.secret,
            )
            if (!isValid) {
                return { success: false, error: 'Invalid webhook signature' }
            }
        }

        const event: WebhookEvent = {
            id: this.generateId(),
            type: (payload['type'] ?? 'threat.detected') as WebhookEventType,
            connector: endpoint.connector,
            timestamp: new Date(),
            payload,
            signature,
        }

        // Update endpoint stats
        endpoint.receivedCount++
        endpoint.lastReceivedAt = new Date()

        // Store in history
        if (this.eventHistory.length >= this.maxHistory) {
            this.eventHistory.shift()
        }
        this.eventHistory.push(event)

        // Dispatch to handlers
        await this.dispatchEvent(event)

        return { success: true }
    }

    // ============================================
    // Dispatch Event to Handlers
    // ============================================

    private async dispatchEvent(event: WebhookEvent): Promise<void> {
        const matchingHandlers = this.handlers.filter((h) => {
            const typeMatch = h.eventType === '*' || h.eventType === event.type
            const connectorMatch = !h.connector || h.connector === event.connector
            return typeMatch && connectorMatch
        })

        await Promise.all(
            matchingHandlers.map(async (h) => {
                try {
                    await h.handler(event)
                } catch (error) {
                    this.emit('error', { handler: h, event, error })
                }
            }),
        )

        // Also emit as EventEmitter event
        this.emit(event.type, event)
        this.emit('*', event)
    }

    // ============================================
    // Verify HMAC Signature
    // ============================================

    private verifySignature(
        payload: string,
        signature: string,
        secret: string,
    ): boolean {
        const expected = crypto
            .createHmac('sha256', secret)
            .update(payload)
            .digest('hex')
        return crypto.timingSafeEqual(
            Buffer.from(signature),
            Buffer.from(expected),
        )
    }

    // ============================================
    // Generate Webhook Secret
    // ============================================

    static generateSecret(): string {
        return crypto.randomBytes(32).toString('hex')
    }

    // ============================================
    // Query History
    // ============================================

    getHistory(filter?: {
        connector?: string
        eventType?: WebhookEventType
        limit?: number
    }): WebhookEvent[] {
        let events = [...this.eventHistory]

        if (filter?.connector) {
            events = events.filter((e) => e.connector === filter.connector)
        }
        if (filter?.eventType) {
            events = events.filter((e) => e.type === filter.eventType)
        }
        if (filter?.limit) {
            events = events.slice(-filter.limit)
        }

        return events.reverse()
    }

    // ============================================
    // Stats
    // ============================================

    getStats() {
        const byConnector: Record<string, number> = {}
        const byType: Record<string, number> = {}

        for (const event of this.eventHistory) {
            byConnector[event.connector] = (byConnector[event.connector] ?? 0) + 1
            byType[event.type] = (byType[event.type] ?? 0) + 1
        }

        return {
            totalEvents: this.eventHistory.length,
            registeredEndpoints: this.endpoints.size,
            registeredHandlers: this.handlers.length,
            byConnector,
            byType,
        }
    }

    getEndpoints(): WebhookEndpoint[] {
        return Array.from(this.endpoints.values())
    }

    // ============================================
    // Utility
    // ============================================

    private generateId(): string {
        return `wh_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`
    }
}

// ============================================
// Global Webhook Manager
// ============================================

export const webhookManager = new WebhookManager({ maxHistory: 1000 })