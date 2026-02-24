// ============================================
// MANAGEENGINE CONNECTOR - Complyment Connectors SDK
// ============================================

import { BaseConnector } from '../../core/BaseConnector'
import {
    ConnectorConfig,
    ConnectorResponse,
    NormalizedVulnerability,
    NormalizedAsset,
    AuthType,
    LogLevel,
} from '../../core/types'
import {
    ManageEngineConfig,
    ManageEnginePatch,
    ManageEnginePatchFilter,
    ManageEnginePatchListResponse,
    ManageEngineComputer,
    ManageEngineComputerFilter,
    ManageEngineComputerListResponse,
    ManageEngineDeployment,
    ManageEngineDeploymentFilter,
    ManageEngineVulnerability,
} from './types'

export class ManageEngineConnector extends BaseConnector {
    private refreshToken: string
    private clientId: string
    private clientSecret: string

    constructor(meConfig: ManageEngineConfig) {
        const config: ConnectorConfig = {
            name: 'manageengine',
            baseUrl: meConfig.baseUrl,
            auth: {
                type: AuthType.OAUTH2,
                clientId: meConfig.clientId,
                clientSecret: meConfig.clientSecret,
                tokenUrl: `${meConfig.baseUrl}/oauth/token`,
            },
            timeout: meConfig.timeout ?? 30000,
            retries: meConfig.retries ?? 3,
            cache: meConfig.cache,
            dryRun: meConfig.dryRun,
            logger: LogLevel.INFO,
        }
        super(config)
        this.refreshToken = meConfig.refreshToken
        this.clientId = meConfig.clientId
        this.clientSecret = meConfig.clientSecret
    }

    // ============================================
    // Auth - OAuth2 with Refresh Token
    // ============================================

    async authenticate(): Promise<void> {
        const response = await this.post<{
            access_token: string
            expires_in: number
        }>('/oauth/token', {
            grant_type: 'refresh_token',
            client_id: this.clientId,
            client_secret: this.clientSecret,
            refresh_token: this.refreshToken,
        })

        if (response.data) {
            this.setToken(response.data.access_token, response.data.expires_in)
        }
    }

    async testConnection(): Promise<boolean> {
        try {
            await this.authenticate()
            await this.get('/api/1.3/patch/allpatches', { pagenumber: 1, pagesize: 1 })
            return true
        } catch {
            return false
        }
    }

    // ============================================
    // Patch Management
    // ============================================

    async getPatches(
        filter?: ManageEnginePatchFilter,
    ): Promise<ConnectorResponse<ManageEnginePatchListResponse>> {
        const params: Record<string, unknown> = {
            pagenumber: filter?.page ?? 1,
            pagesize: filter?.limit ?? 50,
        }

        if (filter?.severity?.length) params['severity'] = filter.severity.join(',')
        if (filter?.status?.length) params['patchstatus'] = filter.status.join(',')
        if (filter?.rebootRequired !== undefined) params['rebootrequired'] = filter.rebootRequired

        return this.get<ManageEnginePatchListResponse>(
            '/api/1.3/patch/allpatches',
            params,
        )
    }

    async getMissingPatches(
        computerId?: string,
    ): Promise<ConnectorResponse<ManageEnginePatchListResponse>> {
        const params: Record<string, unknown> = {
            pagenumber: 1,
            pagesize: 100,
            patchstatus: 'Missing',
        }

        if (computerId) params['computerid'] = computerId

        return this.get<ManageEnginePatchListResponse>(
            '/api/1.3/patch/allpatches',
            params,
        )
    }

    async getCriticalPatches(): Promise<ConnectorResponse<ManageEnginePatchListResponse>> {
        return this.getPatches({
            severity: ['Critical', 'Important'],
            status: ['Missing'],
        })
    }

    async getPatchById(
        patchId: string,
    ): Promise<ConnectorResponse<ManageEnginePatch>> {
        return this.get<ManageEnginePatch>(`/api/1.3/patch/${patchId}`)
    }

    // ============================================
    // Computer Management
    // ============================================

    async getComputers(
        meFilter?: ManageEngineComputerFilter,
    ): Promise<ConnectorResponse<ManageEngineComputerListResponse>> {
        const params: Record<string, unknown> = {
            pagenumber: meFilter?.page ?? 1,
            pagesize: meFilter?.limit ?? 50,
        }

        if (meFilter?.status?.length) params['status'] = meFilter.status.join(',')
        if (meFilter?.domain) params['domain'] = meFilter.domain
        if (meFilter?.os) params['os'] = meFilter.os
        if (meFilter?.computerName) params['computername'] = meFilter.computerName

        return this.get<ManageEngineComputerListResponse>(
            '/api/1.3/patch/allsystems',
            params,
            true, // cache
        )
    }
}