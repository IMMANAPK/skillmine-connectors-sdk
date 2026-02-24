// ============================================
// QUALYS CONNECTOR - Complyment Connectors SDK
// ============================================

import { BaseConnector } from '../../core/BaseConnector'
import {
    ConnectorConfig,
    ConnectorResponse,
    NormalizedVulnerability,
    NormalizedAsset,
    PaginatedResponse,
    AuthType,
    LogLevel,
} from '../../core/types'
import {
    QualysConfig,
    QualysAsset,
    QualysAssetFilter,
    QualysAssetListResponse,
    QualysVulnerability,
    QualysVulnFilter,
    QualysVulnListResponse,
    QualysScan,
    QualysScanFilter,
    QualysScanListResponse,
    QualysReport,
    QualysComplianceControl,
} from './types'

export class QualysConnector extends BaseConnector {
    constructor(qualysConfig: QualysConfig) {
        // Map QualysConfig → ConnectorConfig
        const config: ConnectorConfig = {
            name: 'qualys',
            baseUrl: qualysConfig.baseUrl,
            auth: {
                type: AuthType.BASIC,
                username: qualysConfig.username,
                password: qualysConfig.password,
            },
            timeout: qualysConfig.timeout ?? 30000,
            retries: qualysConfig.retries ?? 3,
            cache: qualysConfig.cache,
            dryRun: qualysConfig.dryRun,
            logger: LogLevel.INFO,
        }
        super(config)
    }

    // ============================================
    // Auth - Basic Auth (handled by BaseConnector)
    // ============================================

    async authenticate(): Promise<void> {
        // Basic auth is injected automatically by BaseConnector
        // No token fetch needed
    }

    async testConnection(): Promise<boolean> {
        try {
            await this.get('/api/2.0/fo/user/?action=list')
            return true
        } catch {
            return false
        }
    }

    // ============================================
    // Asset Management
    // ============================================

    async getAssets(
        filter?: QualysAssetFilter,
    ): Promise<ConnectorResponse<PaginatedResponse<QualysAsset>>> {
        const params: Record<string, unknown> = {
            action: 'list',
            page: filter?.page ?? 1,
            page_size: filter?.limit ?? 50,
        }

        if (filter?.hostname) params['hostname'] = filter.hostname
        if (filter?.ipAddress) params['ips'] = filter.ipAddress
        if (filter?.os) params['os'] = filter.os
        if (filter?.tags) params['tag_name'] = filter.tags.join(',')

        const response = await this.get<QualysAssetListResponse>(
            '/api/2.0/fo/asset/host/',
            params,
            true, // use cache
        )

        if (response.data) {
            const paginated = this.buildPaginatedResponse(
                response.data.assets,
                response.data.total,
                { page: filter?.page, limit: filter?.limit },
            )
            return { ...response, data: paginated }
        }

        return response as unknown as ConnectorResponse<PaginatedResponse<QualysAsset>>
    }

    async getAssetById(
        assetId: string,
    ): Promise<ConnectorResponse<QualysAsset>> {
        return this.get<QualysAsset>(
            `/api/2.0/fo/asset/host/`,
            { action: 'list', ids: assetId },
        )
    }

    // ============================================
    // Vulnerability Management
    // ============================================

    async getVulnerabilities(
        filter?: QualysVulnFilter,
    ): Promise<ConnectorResponse<PaginatedResponse<QualysVulnerability>>> {
        const params: Record<string, unknown> = {
            action: 'list',
            page: filter?.page ?? 1,
            page_size: filter?.limit ?? 50,
        }

        if (filter?.severity?.length) params['severities'] = filter.severity.join(',')
        if (filter?.status?.length) params['status'] = filter.status.join(',')
        if (filter?.hostname) params['hostname'] = filter.hostname
        if (filter?.ipAddress) params['ips'] = filter.ipAddress
        if (filter?.cve) params['cve_id'] = filter.cve

        const response = await this.get<QualysVulnListResponse>(
            '/api/2.0/fo/asset/host/vm/detection/',
            params,
        )

        if (response.data) {
            const paginated = this.buildPaginatedResponse(
                response.data.vulnerabilities,
                response.data.total,
                { page: filter?.page, limit: filter?.limit },
            )
            return { ...response, data: paginated }
        }

        return response as unknown as ConnectorResponse<PaginatedResponse<QualysVulnerability>>
    }

    async getCriticalVulnerabilities(): Promise<
        ConnectorResponse<PaginatedResponse<QualysVulnerability>>
    > {
        return this.getVulnerabilities({
            severity: [4, 5],
            status: ['Active', 'New'],
        })
    }

    // ============================================
    // Scan Management
    // ============================================

    async getScans(
        filter?: QualysScanFilter,
    ): Promise<ConnectorResponse<PaginatedResponse<QualysScan>>> {
        const params: Record<string, unknown> = {
            action: 'list',
            page: filter?.page ?? 1,
            page_size: filter?.limit ?? 50,
        }

        if (filter?.status?.length) params['state'] = filter.status.join(',')
        if (filter?.type) params['type'] = filter.type

        const response = await this.get<QualysScanListResponse>(
            '/api/2.0/fo/scan/',
            params,
        )

        if (response.data) {
            const paginated = this.buildPaginatedResponse(
                response.data.scans,
                response.data.total,
                { page: filter?.page, limit: filter?.limit },
            )
            return { ...response, data: paginated }
        }

        return response as unknown as ConnectorResponse<PaginatedResponse<QualysScan>>
    }

    async launchScan(
        title: string,
        targetHosts: string[],
        optionProfileId: string,
    ): Promise<ConnectorResponse<QualysScan>> {
        return this.post<QualysScan>('/api/2.0/fo/scan/', {
            action: 'launch',
            scan_title: title,
            ip: targetHosts.join(','),
            option_id: optionProfileId,
        })
    }

    async cancelScan(scanId: string): Promise<ConnectorResponse<void>> {
        const response = await this.post<void>('/api/2.0/fo/scan/', {
            action: 'cancel',
            scan_ref: scanId,
        })
        return response
    }

    // ============================================
    // Reports
    // ============================================

    async getReports(): Promise<ConnectorResponse<QualysReport[]>> {
        const response = await this.get<QualysReport[]>('/api/2.0/fo/report/', {
            action: 'list',
        })
        return response
    }

    async downloadReport(
        reportId: string,
    ): Promise<ConnectorResponse<Buffer>> {
        const response = await this.get<Buffer>(`/api/2.0/fo/report/`, {
            action: 'fetch',
            id: reportId,
        })
        return response
    }

    // ============================================
    // Compliance
    // ============================================

    async getComplianceControls(): Promise<
        ConnectorResponse<QualysComplianceControl[]>
    > {
        return this.get<QualysComplianceControl[]>(
            '/api/2.0/fo/compliance/control/',
            { action: 'list' },
        )
    }

    // ============================================
    // Normalization - Maps to SDK standard format
    // ============================================

    async getNormalizedVulnerabilities(
        filter?: QualysVulnFilter,
    ): Promise<ConnectorResponse<NormalizedVulnerability[]>> {
        const response = await this.getVulnerabilities(filter)

        if (!response.data) {
            return { ...response, data: [] }
        }

        const normalized: NormalizedVulnerability[] = response.data.data.map(
            (vuln) => ({
                id: vuln.qid,
                title: vuln.title,
                severity: this.mapSeverity(vuln.severity),
                cvss: vuln.cvssV3 ?? vuln.cvssBase,
                cve: vuln.cve?.[0],
                affectedAsset: vuln.affectedHostname ?? vuln.affectedIp,
                source: 'qualys',
                detectedAt: new Date(vuln.firstDetected),
                raw: vuln,
            }),
        )

        return { ...response, data: normalized }
    }

    async getNormalizedAssets(
        filter?: QualysAssetFilter,
    ): Promise<ConnectorResponse<NormalizedAsset[]>> {
        const response = await this.getAssets(filter)

        if (!response.data) {
            return { ...response, data: [] }
        }

        const normalized: NormalizedAsset[] = response.data.data.map((asset) => ({
            id: asset.id,
            hostname: asset.hostname,
            ipAddress: asset.ipAddress,
            os: asset.os,
            type: 'server',
            source: 'qualys',
            lastSeen: new Date(asset.lastSeen),
            raw: asset,
        }))

        return { ...response, data: normalized }
    }

    // ============================================
    // Private Helpers
    // ============================================

    private mapSeverity(
        severity: 1 | 2 | 3 | 4 | 5,
    ): 'critical' | 'high' | 'medium' | 'low' | 'info' {
        const map = {
            5: 'critical',
            4: 'high',
            3: 'medium',
            2: 'low',
            1: 'info',
        } as const
        return map[severity]
    }
}