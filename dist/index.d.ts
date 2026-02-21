import { AxiosInstance } from 'axios';
import { EventEmitter } from 'events';
import { z } from 'zod';

declare enum AuthType {
    API_KEY = "api_key",
    BASIC = "basic",
    OAUTH2 = "oauth2",
    BEARER = "bearer",
    VAULT = "vault"
}
declare enum ConnectorStatus {
    CONNECTED = "connected",
    DISCONNECTED = "disconnected",
    DEGRADED = "degraded",
    ERROR = "error",
    CONNECTING = "connecting"
}
declare enum LogLevel$1 {
    DEBUG = "debug",
    INFO = "info",
    WARN = "warn",
    ERROR = "error"
}
interface ApiKeyAuthConfig {
    type: AuthType.API_KEY;
    apiKey: string;
    headerName?: string;
}
interface BasicAuthConfig {
    type: AuthType.BASIC;
    username: string;
    password: string;
}
interface OAuth2Config {
    type: AuthType.OAUTH2;
    clientId: string;
    clientSecret: string;
    tokenUrl: string;
    scope?: string;
    redirectUri?: string;
}
interface BearerAuthConfig {
    type: AuthType.BEARER;
    token: string;
}
interface VaultAuthConfig {
    type: AuthType.VAULT;
    vaultUrl: string;
    secretPath: string;
    token: string;
}
type AuthConfig = ApiKeyAuthConfig | BasicAuthConfig | OAuth2Config | BearerAuthConfig | VaultAuthConfig;
interface ConnectorConfig {
    name: string;
    baseUrl: string;
    auth: AuthConfig;
    timeout?: number;
    retries?: number;
    rateLimit?: {
        requests: number;
        perSeconds: number;
    };
    cache?: {
        enabled: boolean;
        ttl: number;
    };
    dryRun?: boolean;
    apiVersion?: string;
    telemetry?: boolean;
    logger?: LogLevel$1;
}
interface ConnectorResponse<T = unknown> {
    success: boolean;
    data?: T;
    error?: string;
    statusCode?: number;
    timestamp: Date;
    connector: string;
    cached?: boolean;
    dryRun?: boolean;
}
interface HealthCheckResult {
    connector: string;
    status: ConnectorStatus;
    latency?: number;
    message?: string;
    checkedAt: Date;
}
interface PaginationOptions {
    page?: number;
    limit?: number;
    offset?: number;
    cursor?: string;
}
interface PaginatedResponse<T> {
    data: T[];
    total: number;
    page: number;
    limit: number;
    hasMore: boolean;
    nextCursor?: string;
}
declare enum ConnectorEvent {
    CONNECTED = "connector.connected",
    DISCONNECTED = "connector.disconnected",
    ERROR = "connector.error",
    DATA_FETCHED = "data.fetched",
    RATE_LIMITED = "connector.rate_limited",
    RETRY = "connector.retry",
    CACHE_HIT = "cache.hit",
    CACHE_MISS = "cache.miss"
}
interface NormalizedVulnerability {
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    cvss?: number;
    cve?: string;
    affectedAsset: string;
    source: string;
    detectedAt: Date;
    raw?: unknown;
}
interface NormalizedAsset {
    id: string;
    hostname: string;
    ipAddress: string;
    os?: string;
    type: 'server' | 'workstation' | 'network' | 'cloud' | 'unknown';
    source: string;
    lastSeen: Date;
    raw?: unknown;
}
interface NormalizedThreat {
    id: string;
    name: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    status: 'active' | 'resolved' | 'investigating';
    affectedAsset: string;
    source: string;
    detectedAt: Date;
    raw?: unknown;
}

declare abstract class BaseConnector extends EventEmitter {
    protected config: ConnectorConfig;
    protected httpClient: AxiosInstance;
    protected status: ConnectorStatus;
    protected accessToken?: string;
    protected tokenExpiresAt?: Date;
    private circuitBreaker;
    private readonly failureThreshold;
    private readonly recoveryTimeMs;
    private cache;
    private requestTimestamps;
    constructor(config: ConnectorConfig);
    abstract authenticate(): Promise<void>;
    abstract testConnection(): Promise<boolean>;
    private validateConfig;
    private createHttpClient;
    private injectAuthHeaders;
    protected get<T>(url: string, params?: Record<string, unknown>, useCache?: boolean): Promise<ConnectorResponse<T>>;
    protected post<T>(url: string, body?: unknown, useCache?: boolean): Promise<ConnectorResponse<T>>;
    protected put<T>(url: string, body?: unknown): Promise<ConnectorResponse<T>>;
    protected delete<T>(url: string): Promise<ConnectorResponse<T>>;
    private executeWithRetry;
    private checkCircuitBreaker;
    private recordCircuitBreakerFailure;
    private resetCircuitBreaker;
    private checkRateLimit;
    private getFromCache;
    private setCache;
    clearCache(): void;
    healthCheck(): Promise<HealthCheckResult>;
    protected buildPaginatedResponse<T>(data: T[], total: number, options: PaginationOptions): PaginatedResponse<T>;
    protected isTokenExpired(): boolean;
    protected setToken(token: string, expiresInSeconds: number): void;
    private dryRunResponse;
    protected log(level: LogLevel$1, message: string, meta?: unknown): void;
    private sleep;
    getStatus(): ConnectorStatus;
    getConfig(): Omit<ConnectorConfig, 'auth'>;
}

declare class ConnectorRegistry {
    private connectors;
    register(name: string, connector: BaseConnector): void;
    get<T extends BaseConnector>(name: string): T;
    has(name: string): boolean;
    unregister(name: string): void;
    healthCheckAll(): Promise<Record<string, HealthCheckResult>>;
    list(): string[];
    size(): number;
    clear(): void;
}
declare const registry: ConnectorRegistry;

declare class SDKError extends Error {
    readonly code: string;
    readonly connector?: string | undefined;
    readonly statusCode?: number | undefined;
    constructor(message: string, code: string, connector?: string | undefined, statusCode?: number | undefined);
}
declare class AuthenticationError extends SDKError {
    constructor(connector: string, message?: string);
}
declare class TokenExpiredError extends SDKError {
    constructor(connector: string);
}
declare class InvalidCredentialsError extends SDKError {
    constructor(connector: string);
}
declare class ConnectionError extends SDKError {
    constructor(connector: string, message?: string);
}
declare class TimeoutError extends SDKError {
    constructor(connector: string, timeoutMs: number);
}
declare class RateLimitError extends SDKError {
    readonly retryAfter?: number | undefined;
    constructor(connector: string, retryAfter?: number | undefined);
}
declare class ValidationError extends SDKError {
    readonly field?: string | undefined;
    constructor(message: string, field?: string | undefined);
}
declare class ConfigurationError extends SDKError {
    constructor(message: string, connector?: string);
}
declare class APIError extends SDKError {
    readonly response?: unknown | undefined;
    constructor(connector: string, statusCode: number, message: string, response?: unknown | undefined);
}
declare class NotFoundError extends SDKError {
    constructor(connector: string, resource: string);
}
declare class CircuitBreakerOpenError extends SDKError {
    constructor(connector: string);
}
declare class PluginNotFoundError extends SDKError {
    constructor(connectorName: string);
}
declare class DuplicatePluginError extends SDKError {
    constructor(connectorName: string);
}

interface QualysConfig {
    baseUrl: string;
    username: string;
    password: string;
    timeout?: number;
    retries?: number;
    cache?: {
        enabled: boolean;
        ttl: number;
    };
    dryRun?: boolean;
}
interface QualysAsset {
    id: string;
    hostname: string;
    ipAddress: string;
    os?: string;
    osVersion?: string;
    type: string;
    lastSeen: string;
    tags?: string[];
    netbiosName?: string;
    dnsName?: string;
    agentId?: string;
}
interface QualysAssetListResponse {
    assets: QualysAsset[];
    total: number;
    page: number;
    limit: number;
}
type QualysSeverity = 1 | 2 | 3 | 4 | 5;
interface QualysVulnerability {
    qid: string;
    title: string;
    severity: QualysSeverity;
    cvssBase?: number;
    cvssV3?: number;
    cve?: string[];
    affectedHostname: string;
    affectedIp: string;
    firstDetected: string;
    lastDetected: string;
    status: 'Active' | 'Fixed' | 'New' | 'Re-Opened';
    category?: string;
    solution?: string;
    description?: string;
}
interface QualysVulnListResponse {
    vulnerabilities: QualysVulnerability[];
    total: number;
    page: number;
    limit: number;
}
type QualysScanStatus = 'Running' | 'Finished' | 'Paused' | 'Cancelled' | 'Error';
interface QualysScan {
    id: string;
    title: string;
    status: QualysScanStatus;
    type: 'Vulnerability' | 'Compliance' | 'Web Application';
    launchedAt: string;
    completedAt?: string;
    targetHosts?: string[];
    duration?: number;
}
interface QualysScanListResponse {
    scans: QualysScan[];
    total: number;
}
interface QualysReport {
    id: string;
    title: string;
    type: string;
    status: 'Finished' | 'Running' | 'Submitted' | 'Cancelled';
    createdAt: string;
    size?: number;
    format: 'PDF' | 'HTML' | 'XML' | 'CSV' | 'DOCX';
}
interface QualysComplianceControl {
    id: string;
    title: string;
    status: 'Pass' | 'Fail' | 'Error' | 'Exception';
    severity: QualysSeverity;
    standard: string;
    section: string;
    lastChecked: string;
}
interface QualysVulnFilter {
    severity?: QualysSeverity[];
    status?: ('Active' | 'Fixed' | 'New' | 'Re-Opened')[];
    hostname?: string;
    ipAddress?: string;
    cve?: string;
    page?: number;
    limit?: number;
}
interface QualysAssetFilter {
    hostname?: string;
    ipAddress?: string;
    os?: string;
    tags?: string[];
    page?: number;
    limit?: number;
}
interface QualysScanFilter {
    status?: QualysScanStatus[];
    type?: string;
    page?: number;
    limit?: number;
}

declare class QualysConnector extends BaseConnector {
    constructor(qualysConfig: QualysConfig);
    authenticate(): Promise<void>;
    testConnection(): Promise<boolean>;
    getAssets(filter?: QualysAssetFilter): Promise<ConnectorResponse<PaginatedResponse<QualysAsset>>>;
    getAssetById(assetId: string): Promise<ConnectorResponse<QualysAsset>>;
    getVulnerabilities(filter?: QualysVulnFilter): Promise<ConnectorResponse<PaginatedResponse<QualysVulnerability>>>;
    getCriticalVulnerabilities(): Promise<ConnectorResponse<PaginatedResponse<QualysVulnerability>>>;
    getScans(filter?: QualysScanFilter): Promise<ConnectorResponse<PaginatedResponse<QualysScan>>>;
    launchScan(title: string, targetHosts: string[], optionProfileId: string): Promise<ConnectorResponse<QualysScan>>;
    cancelScan(scanId: string): Promise<ConnectorResponse<void>>;
    getReports(): Promise<ConnectorResponse<QualysReport[]>>;
    downloadReport(reportId: string): Promise<ConnectorResponse<Buffer>>;
    getComplianceControls(): Promise<ConnectorResponse<QualysComplianceControl[]>>;
    getNormalizedVulnerabilities(filter?: QualysVulnFilter): Promise<ConnectorResponse<NormalizedVulnerability[]>>;
    getNormalizedAssets(filter?: QualysAssetFilter): Promise<ConnectorResponse<NormalizedAsset[]>>;
    private mapSeverity;
}

interface SentinelOneConfig {
    baseUrl: string;
    apiToken: string;
    timeout?: number;
    retries?: number;
    cache?: {
        enabled: boolean;
        ttl: number;
    };
    dryRun?: boolean;
}
type SentinelOneAgentStatus = 'connected' | 'disconnected' | 'degraded';
interface SentinelOneAgent {
    id: string;
    computerName: string;
    ipAddress: string;
    osName: string;
    osVersion: string;
    status: SentinelOneAgentStatus;
    infected: boolean;
    isActive: boolean;
    lastActiveDate: string;
    agentVersion: string;
    domain?: string;
    siteName?: string;
    groupName?: string;
    tags?: string[];
    networkStatus: 'connected' | 'disconnected' | 'connecting';
    threatCount: number;
    mitigationMode: 'protect' | 'detect' | 'none';
}
interface SentinelOneAgentListResponse {
    data: SentinelOneAgent[];
    pagination: {
        totalItems: number;
        nextCursor?: string;
    };
}
type SentinelOneThreatStatus = 'active' | 'mitigated' | 'resolved' | 'suspicious' | 'blocked';
type SentinelOneConfidenceLevel = 'malicious' | 'suspicious' | 'n/a';
interface SentinelOneThreat {
    id: string;
    threatName: string;
    classification: string;
    confidenceLevel: SentinelOneConfidenceLevel;
    mitigationStatus: SentinelOneThreatStatus;
    agentComputerName: string;
    agentId: string;
    filePath?: string;
    fileHash?: string;
    createdAt: string;
    updatedAt: string;
    siteName?: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    engines: string[];
    indicators?: string[];
}
interface SentinelOneThreatListResponse {
    data: SentinelOneThreat[];
    pagination: {
        totalItems: number;
        nextCursor?: string;
    };
}
interface SentinelOneActivity {
    id: string;
    activityType: number;
    agentId?: string;
    agentUpdatedVersion?: string;
    createdAt: string;
    data: Record<string, unknown>;
    siteId?: string;
    threatId?: string;
    userId?: string;
    primaryDescription: string;
    secondaryDescription?: string;
}
interface SentinelOneGroup {
    id: string;
    name: string;
    type: 'static' | 'dynamic';
    agentCount: number;
    siteId: string;
    rank?: number;
}
interface SentinelOneSite {
    id: string;
    name: string;
    state: 'active' | 'expired' | 'deleted';
    agentCount: number;
    activeLicenses: number;
    totalLicenses: number;
    createdAt: string;
}
interface SentinelOneAgentFilter {
    status?: SentinelOneAgentStatus[];
    infected?: boolean;
    osName?: string;
    groupName?: string;
    siteName?: string;
    computerName?: string;
    limit?: number;
    cursor?: string;
}
interface SentinelOneThreatFilter {
    status?: SentinelOneThreatStatus[];
    severity?: ('critical' | 'high' | 'medium' | 'low')[];
    confidenceLevel?: SentinelOneConfidenceLevel[];
    agentId?: string;
    limit?: number;
    cursor?: string;
    createdAfter?: string;
    createdBefore?: string;
}
type MitigationAction = 'kill' | 'quarantine' | 'remediate' | 'rollback-remediation' | 'un-quarantine';
interface MitigationRequest {
    threatIds: string[];
    action: MitigationAction;
}
interface MitigationResponse {
    affected: number;
    success: boolean;
}

declare class SentinelOneConnector extends BaseConnector {
    constructor(s1Config: SentinelOneConfig);
    authenticate(): Promise<void>;
    testConnection(): Promise<boolean>;
    getAgents(filter?: SentinelOneAgentFilter): Promise<ConnectorResponse<SentinelOneAgentListResponse>>;
    getAgentById(agentId: string): Promise<ConnectorResponse<SentinelOneAgent>>;
    getInfectedAgents(): Promise<ConnectorResponse<SentinelOneAgentListResponse>>;
    disconnectAgentFromNetwork(agentId: string): Promise<ConnectorResponse<void>>;
    reconnectAgentToNetwork(agentId: string): Promise<ConnectorResponse<void>>;
    initiateAgentScan(agentId: string): Promise<ConnectorResponse<void>>;
    getThreats(filter?: SentinelOneThreatFilter): Promise<ConnectorResponse<SentinelOneThreatListResponse>>;
    getActiveThreatCount(): Promise<number>;
    getCriticalThreats(): Promise<ConnectorResponse<SentinelOneThreatListResponse>>;
    mitigateThreats(request: MitigationRequest): Promise<ConnectorResponse<MitigationResponse>>;
    quarantineThreat(threatId: string): Promise<ConnectorResponse<MitigationResponse>>;
    killThreat(threatId: string): Promise<ConnectorResponse<MitigationResponse>>;
    remediateThreat(threatId: string): Promise<ConnectorResponse<MitigationResponse>>;
    getActivities(limit?: number): Promise<ConnectorResponse<SentinelOneActivity[]>>;
    getGroups(): Promise<ConnectorResponse<SentinelOneGroup[]>>;
    getSites(): Promise<ConnectorResponse<SentinelOneSite[]>>;
    getNormalizedThreats(filter?: SentinelOneThreatFilter): Promise<ConnectorResponse<NormalizedThreat[]>>;
    getNormalizedAssets(filter?: SentinelOneAgentFilter): Promise<ConnectorResponse<NormalizedAsset[]>>;
    private mapThreatStatus;
}

interface CheckpointConfig {
    baseUrl: string;
    username: string;
    password: string;
    domain?: string;
    timeout?: number;
    retries?: number;
    cache?: {
        enabled: boolean;
        ttl: number;
    };
    dryRun?: boolean;
}
interface CheckpointSession {
    sid: string;
    uid: string;
    url: string;
    sessionTimeout: number;
    lastLoginWasAt: string;
}
type CheckpointRuleAction = 'Accept' | 'Drop' | 'Reject' | 'Ask' | 'Inform';
interface CheckpointRule {
    uid: string;
    name: string;
    enabled: boolean;
    action: CheckpointRuleAction;
    source: string[];
    destination: string[];
    service: string[];
    track: string;
    comments?: string;
    installOn: string[];
}
interface CheckpointPolicy {
    uid: string;
    name: string;
    type: string;
    rules: CheckpointRule[];
    installedOn?: string[];
}
interface CheckpointHost {
    uid: string;
    name: string;
    ipAddress: string;
    subnetMask?: string;
    comments?: string;
    groups?: string[];
}
interface CheckpointNetwork {
    uid: string;
    name: string;
    subnet: string;
    subnetMask: string;
    comments?: string;
}
interface CheckpointGroup {
    uid: string;
    name: string;
    members: string[];
    comments?: string;
}
type CheckpointThreatSeverity = 'Critical' | 'High' | 'Medium' | 'Low';
interface CheckpointThreat {
    uid: string;
    name: string;
    severity: CheckpointThreatSeverity;
    confidence: 'High' | 'Medium' | 'Low';
    performanceImpact: 'High' | 'Medium' | 'Low';
    protectionType: string;
    affectedSystems: string[];
    cve?: string[];
}
interface CheckpointLog {
    id: string;
    time: string;
    action: string;
    origin: string;
    sourceIp: string;
    destinationIp: string;
    service: string;
    blade: string;
    severity?: CheckpointThreatSeverity;
    description?: string;
}
interface CheckpointLogFilter {
    startTime?: string;
    endTime?: string;
    action?: string;
    sourceIp?: string;
    destinationIp?: string;
    severity?: CheckpointThreatSeverity[];
    limit?: number;
}
type CheckpointGatewayStatus = 'OK' | 'Warning' | 'Error' | 'Disconnected';
interface CheckpointGateway {
    uid: string;
    name: string;
    ipAddress: string;
    osName: string;
    version: string;
    status: CheckpointGatewayStatus;
    blades: string[];
    lastUpdateTime: string;
}
interface CheckpointRuleFilter {
    policyName?: string;
    enabled?: boolean;
    action?: CheckpointRuleAction;
    limit?: number;
    offset?: number;
}
interface CheckpointHostFilter {
    name?: string;
    ipAddress?: string;
    limit?: number;
    offset?: number;
}

declare class CheckpointConnector extends BaseConnector {
    private session?;
    private domain?;
    constructor(cpConfig: CheckpointConfig);
    authenticate(): Promise<void>;
    logout(): Promise<void>;
    testConnection(): Promise<boolean>;
    getPolicies(): Promise<ConnectorResponse<CheckpointPolicy[]>>;
    getRules(filter?: CheckpointRuleFilter): Promise<ConnectorResponse<CheckpointRule[]>>;
    addRule(policyName: string, rule: Partial<CheckpointRule>): Promise<ConnectorResponse<CheckpointRule>>;
    updateRule(ruleUid: string, policyName: string, updates: Partial<CheckpointRule>): Promise<ConnectorResponse<CheckpointRule>>;
    deleteRule(ruleUid: string, policyName: string): Promise<ConnectorResponse<void>>;
    publishChanges(): Promise<ConnectorResponse<void>>;
    discardChanges(): Promise<ConnectorResponse<void>>;
    installPolicy(policyName: string, targets: string[]): Promise<ConnectorResponse<void>>;
    getHosts(filter?: CheckpointHostFilter): Promise<ConnectorResponse<CheckpointHost[]>>;
    addHost(name: string, ipAddress: string, comments?: string): Promise<ConnectorResponse<CheckpointHost>>;
    deleteHost(uid: string): Promise<ConnectorResponse<void>>;
    getNetworks(): Promise<ConnectorResponse<CheckpointNetwork[]>>;
    getGroups(): Promise<ConnectorResponse<CheckpointGroup[]>>;
    getThreats(): Promise<ConnectorResponse<CheckpointThreat[]>>;
    blockThreat(threatUid: string): Promise<ConnectorResponse<void>>;
    getLogs(filter?: CheckpointLogFilter): Promise<ConnectorResponse<CheckpointLog[]>>;
    getGateways(): Promise<ConnectorResponse<CheckpointGateway[]>>;
    getGatewayStatus(gatewayUid: string): Promise<ConnectorResponse<CheckpointGateway>>;
    getNormalizedThreats(): Promise<ConnectorResponse<NormalizedThreat[]>>;
    getNormalizedAssets(): Promise<ConnectorResponse<NormalizedAsset[]>>;
}

interface ManageEngineConfig {
    baseUrl: string;
    clientId: string;
    clientSecret: string;
    refreshToken: string;
    timeout?: number;
    retries?: number;
    cache?: {
        enabled: boolean;
        ttl: number;
    };
    dryRun?: boolean;
}
type PatchStatus = 'Missing' | 'Installed' | 'Failed' | 'NotApplicable' | 'Pending';
type PatchSeverity = 'Critical' | 'Important' | 'Moderate' | 'Low' | 'Unrated';
interface ManageEnginePatch {
    patchId: string;
    title: string;
    severity: PatchSeverity;
    status: PatchStatus;
    kb?: string;
    cve?: string[];
    releaseDate: string;
    installDate?: string;
    affectedComputers: number;
    bulletinId?: string;
    description?: string;
    rebootRequired: boolean;
}
interface ManageEnginePatchListResponse {
    patches: ManageEnginePatch[];
    total: number;
    page: number;
    limit: number;
}
type ComputerStatus = 'Live' | 'Down' | 'Unknown';
interface ManageEngineComputer {
    computerId: string;
    computerName: string;
    ipAddress: string;
    os: string;
    osVersion: string;
    domain?: string;
    status: ComputerStatus;
    lastContact: string;
    agentVersion?: string;
    missingPatchCount: number;
    installedPatchCount: number;
    pendingPatchCount: number;
    groups?: string[];
}
interface ManageEngineComputerListResponse {
    computers: ManageEngineComputer[];
    total: number;
    page: number;
    limit: number;
}
type DeploymentStatus = 'Success' | 'Failed' | 'InProgress' | 'Pending' | 'Cancelled';
interface ManageEngineDeployment {
    deploymentId: string;
    name: string;
    status: DeploymentStatus;
    patchIds: string[];
    targetComputers: string[];
    scheduledAt: string;
    completedAt?: string;
    successCount: number;
    failureCount: number;
    pendingCount: number;
}
interface ManageEngineVulnerability {
    vulnerabilityId: string;
    title: string;
    severity: PatchSeverity;
    cve: string[];
    affectedComputerId: string;
    affectedComputerName: string;
    patchAvailable: boolean;
    patchId?: string;
    detectedAt: string;
}
interface ManageEnginePatchFilter {
    severity?: PatchSeverity[];
    status?: PatchStatus[];
    rebootRequired?: boolean;
    page?: number;
    limit?: number;
}
interface ManageEngineComputerFilter {
    status?: ComputerStatus[];
    domain?: string;
    os?: string;
    computerName?: string;
    page?: number;
    limit?: number;
}
interface ManageEngineDeploymentFilter {
    status?: DeploymentStatus[];
    page?: number;
    limit?: number;
}

declare class ManageEngineConnector extends BaseConnector {
    private refreshToken;
    private clientId;
    private clientSecret;
    constructor(meConfig: ManageEngineConfig);
    authenticate(): Promise<void>;
    testConnection(): Promise<boolean>;
    getPatches(filter?: ManageEnginePatchFilter): Promise<ConnectorResponse<ManageEnginePatchListResponse>>;
    getMissingPatches(computerId?: string): Promise<ConnectorResponse<ManageEnginePatchListResponse>>;
    getCriticalPatches(): Promise<ConnectorResponse<ManageEnginePatchListResponse>>;
    getPatchById(patchId: string): Promise<ConnectorResponse<ManageEnginePatch>>;
    getComputers(meFilter?: ManageEngineComputerFilter): Promise<ConnectorResponse<ManageEngineComputerListResponse>>;
}

interface JiraConfig {
    baseUrl: string;
    email: string;
    apiToken: string;
    timeout?: number;
    retries?: number;
    cache?: {
        enabled: boolean;
        ttl: number;
    };
    dryRun?: boolean;
}
interface JiraProject {
    id: string;
    key: string;
    name: string;
    projectTypeKey: string;
    style: string;
    isPrivate: boolean;
    lead?: {
        accountId: string;
        displayName: string;
    };
}
type JiraIssuePriority = 'Highest' | 'High' | 'Medium' | 'Low' | 'Lowest';
type JiraIssueStatus = 'To Do' | 'In Progress' | 'Done' | 'Blocked' | 'In Review';
type JiraIssueType = 'Bug' | 'Task' | 'Story' | 'Epic' | 'Subtask';
interface JiraUser {
    accountId: string;
    displayName: string;
    emailAddress?: string;
    active: boolean;
}
interface JiraIssue {
    id: string;
    key: string;
    summary: string;
    description?: string;
    status: JiraIssueStatus;
    priority: JiraIssuePriority;
    issueType: JiraIssueType;
    projectKey: string;
    assignee?: JiraUser;
    reporter?: JiraUser;
    labels?: string[];
    createdAt: string;
    updatedAt: string;
    dueDate?: string;
    resolvedAt?: string;
    components?: string[];
    customFields?: Record<string, unknown>;
}
interface JiraIssueListResponse {
    issues: JiraIssue[];
    total: number;
    startAt: number;
    maxResults: number;
}
interface JiraCreateIssueRequest {
    projectKey: string;
    summary: string;
    description?: string;
    issueType: JiraIssueType;
    priority?: JiraIssuePriority;
    assigneeAccountId?: string;
    labels?: string[];
    dueDate?: string;
    components?: string[];
    customFields?: Record<string, unknown>;
}
interface JiraUpdateIssueRequest {
    summary?: string;
    description?: string;
    priority?: JiraIssuePriority;
    assigneeAccountId?: string;
    labels?: string[];
    dueDate?: string;
    status?: JiraIssueStatus;
}
interface JiraComment {
    id: string;
    body: string;
    author: JiraUser;
    createdAt: string;
    updatedAt: string;
}
interface JiraTransition {
    id: string;
    name: string;
    to: {
        id: string;
        name: string;
    };
}
type JiraSprintState = 'active' | 'closed' | 'future';
interface JiraSprint {
    id: number;
    name: string;
    state: JiraSprintState;
    startDate?: string;
    endDate?: string;
    completeDate?: string;
    goal?: string;
}
interface JiraIssueFilter {
    projectKey?: string;
    status?: JiraIssueStatus[];
    priority?: JiraIssuePriority[];
    issueType?: JiraIssueType[];
    assigneeAccountId?: string;
    labels?: string[];
    createdAfter?: string;
    createdBefore?: string;
    jql?: string;
    startAt?: number;
    maxResults?: number;
}

declare class JiraConnector extends BaseConnector {
    constructor(jiraConfig: JiraConfig);
    authenticate(): Promise<void>;
    testConnection(): Promise<boolean>;
    getProjects(): Promise<ConnectorResponse<JiraProject[]>>;
    getProjectByKey(projectKey: string): Promise<ConnectorResponse<JiraProject>>;
    getIssues(filter?: JiraIssueFilter): Promise<ConnectorResponse<PaginatedResponse<JiraIssue>>>;
    getIssueByKey(issueKey: string): Promise<ConnectorResponse<JiraIssue>>;
    createIssue(request: JiraCreateIssueRequest): Promise<ConnectorResponse<JiraIssue>>;
    updateIssue(issueKey: string, request: JiraUpdateIssueRequest): Promise<ConnectorResponse<void>>;
    deleteIssue(issueKey: string): Promise<ConnectorResponse<void>>;
    bulkCreateIssues(requests: JiraCreateIssueRequest[]): Promise<ConnectorResponse<JiraIssue[]>>;
    getComments(issueKey: string): Promise<ConnectorResponse<JiraComment[]>>;
    addComment(issueKey: string, body: string): Promise<ConnectorResponse<JiraComment>>;
    getTransitions(issueKey: string): Promise<ConnectorResponse<JiraTransition[]>>;
    transitionIssue(issueKey: string, transitionId: string, comment?: string): Promise<ConnectorResponse<void>>;
    getSprints(boardId: number): Promise<ConnectorResponse<JiraSprint[]>>;
    getActiveSprint(boardId: number): Promise<ConnectorResponse<JiraSprint | null>>;
    createSecurityTicket(projectKey: string, title: string, description: string, severity: 'critical' | 'high' | 'medium' | 'low', source: string): Promise<ConnectorResponse<JiraIssue>>;
}

interface ZohoConfig {
    baseUrl: string;
    clientId: string;
    clientSecret: string;
    refreshToken: string;
    accountsUrl?: string;
    timeout?: number;
    retries?: number;
    cache?: {
        enabled: boolean;
        ttl: number;
    };
    dryRun?: boolean;
}
interface ZohoContact {
    id: string;
    firstName?: string;
    lastName: string;
    email?: string;
    phone?: string;
    mobile?: string;
    accountName?: string;
    title?: string;
    department?: string;
    leadSource?: string;
    createdAt: string;
    updatedAt: string;
    ownerId?: string;
}
interface ZohoContactListResponse {
    data: ZohoContact[];
    info: {
        count: number;
        moreRecords: boolean;
        page: number;
        perPage: number;
    };
}
type ZohoLeadStatus = 'Not Contacted' | 'Attempted to Contact' | 'Contact in Future' | 'Contacted' | 'Junk Lead' | 'Lost Lead' | 'Not Qualified' | 'Pre-Qualified';
interface ZohoLead {
    id: string;
    firstName?: string;
    lastName: string;
    email?: string;
    phone?: string;
    company: string;
    title?: string;
    status: ZohoLeadStatus;
    leadSource?: string;
    industry?: string;
    annualRevenue?: number;
    noOfEmployees?: number;
    rating?: string;
    website?: string;
    createdAt: string;
    updatedAt: string;
}
interface ZohoAccount {
    id: string;
    accountName: string;
    website?: string;
    phone?: string;
    industry?: string;
    annualRevenue?: number;
    noOfEmployees?: number;
    billingCity?: string;
    billingCountry?: string;
    description?: string;
    createdAt: string;
    updatedAt: string;
}
type ZohoDealStage = 'Qualification' | 'Needs Analysis' | 'Value Proposition' | 'Id. Decision Makers' | 'Perception Analysis' | 'Proposal/Price Quote' | 'Negotiation/Review' | 'Closed Won' | 'Closed Lost';
interface ZohoDeal {
    id: string;
    dealName: string;
    accountName?: string;
    stage: ZohoDealStage;
    amount?: number;
    closingDate?: string;
    probability?: number;
    leadSource?: string;
    contactName?: string;
    description?: string;
    createdAt: string;
    updatedAt: string;
}
type ZohoTaskStatus = 'Not Started' | 'Deferred' | 'In Progress' | 'Completed' | 'Waiting for input';
interface ZohoTask {
    id: string;
    subject: string;
    status: ZohoTaskStatus;
    dueDate?: string;
    priority?: 'High' | 'Medium' | 'Low';
    description?: string;
    contactId?: string;
    accountId?: string;
    dealId?: string;
    createdAt: string;
    updatedAt: string;
}
interface ZohoContactFilter {
    page?: number;
    perPage?: number;
    searchBy?: string;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
}
interface ZohoLeadFilter {
    page?: number;
    perPage?: number;
    status?: ZohoLeadStatus[];
    searchBy?: string;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
}
interface ZohoDealFilter {
    page?: number;
    perPage?: number;
    stage?: ZohoDealStage[];
    searchBy?: string;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
}
interface ZohoSearchResponse<T> {
    data: T[];
    info: {
        count: number;
        moreRecords: boolean;
    };
}

declare class ZohoConnector extends BaseConnector {
    private clientId;
    private clientSecret;
    private refreshToken;
    private accountsUrl;
    constructor(zohoConfig: ZohoConfig);
    authenticate(): Promise<void>;
    testConnection(): Promise<boolean>;
    getContacts(filter?: ZohoContactFilter): Promise<ConnectorResponse<PaginatedResponse<ZohoContact>>>;
    getContactById(contactId: string): Promise<ConnectorResponse<ZohoContact>>;
    createContact(contact: Partial<ZohoContact>): Promise<ConnectorResponse<ZohoContact>>;
    updateContact(contactId: string, updates: Partial<ZohoContact>): Promise<ConnectorResponse<ZohoContact>>;
    deleteContact(contactId: string): Promise<ConnectorResponse<void>>;
    getLeads(filter?: ZohoLeadFilter): Promise<ConnectorResponse<PaginatedResponse<ZohoLead>>>;
    getLeadById(leadId: string): Promise<ConnectorResponse<ZohoLead>>;
    createLead(lead: Partial<ZohoLead>): Promise<ConnectorResponse<ZohoLead>>;
    convertLead(leadId: string, accountName: string): Promise<ConnectorResponse<void>>;
    getAccounts(page?: number, perPage?: number): Promise<ConnectorResponse<PaginatedResponse<ZohoAccount>>>;
    getAccountById(accountId: string): Promise<ConnectorResponse<ZohoAccount>>;
    createAccount(account: Partial<ZohoAccount>): Promise<ConnectorResponse<ZohoAccount>>;
    getDeals(filter?: ZohoDealFilter): Promise<ConnectorResponse<PaginatedResponse<ZohoDeal>>>;
    getDealById(dealId: string): Promise<ConnectorResponse<ZohoDeal>>;
    createDeal(deal: Partial<ZohoDeal>): Promise<ConnectorResponse<ZohoDeal>>;
    updateDeal(dealId: string, updates: Partial<ZohoDeal>): Promise<ConnectorResponse<ZohoDeal>>;
    getTasks(): Promise<ConnectorResponse<ZohoTask[]>>;
    createTask(task: Partial<ZohoTask>): Promise<ConnectorResponse<ZohoTask>>;
    searchContacts(query: string): Promise<ConnectorResponse<ZohoSearchResponse<ZohoContact>>>;
    searchLeads(query: string): Promise<ConnectorResponse<ZohoSearchResponse<ZohoLead>>>;
    searchDeals(query: string): Promise<ConnectorResponse<ZohoSearchResponse<ZohoDeal>>>;
    bulkCreateContacts(contacts: Partial<ZohoContact>[]): Promise<ConnectorResponse<ZohoContact[]>>;
    private chunkArray;
}

interface TokenResponse {
    accessToken: string;
    tokenType: string;
    expiresIn: number;
    refreshToken?: string;
    scope?: string;
}
interface OAuth2TokenRequest {
    grantType: 'client_credentials' | 'authorization_code' | 'refresh_token';
    clientId: string;
    clientSecret: string;
    scope?: string;
    code?: string;
    refreshToken?: string;
    redirectUri?: string;
}
interface AuthResult {
    success: boolean;
    token?: string;
    expiresIn?: number;
    error?: string;
}

interface RetryOptions {
    maxRetries?: number;
    initialDelayMs?: number;
    maxDelayMs?: number;
    backoffMultiplier?: number;
    retryableStatusCodes?: number[];
    onRetry?: (attempt: number, error: Error) => void;
}
declare function withRetry<T>(fn: () => Promise<T>, options?: RetryOptions): Promise<T>;
declare class RetryHandler {
    private options;
    constructor(options?: RetryOptions);
    execute<T>(fn: () => Promise<T>): Promise<T>;
    updateOptions(options: Partial<RetryOptions>): void;
}

interface RateLimitOptions {
    maxRequests: number;
    perSeconds: number;
    onThrottled?: (waitMs: number) => void;
}
declare class RateLimiter {
    private tokens;
    private lastRefillTime;
    private readonly maxTokens;
    private readonly refillRate;
    private readonly onThrottled?;
    constructor(options: RateLimitOptions);
    private refill;
    acquire(): Promise<void>;
    tryAcquire(): boolean;
    getState(): {
        tokens: number;
        maxTokens: number;
        utilization: number;
    };
    reset(): void;
    private sleep;
}
declare class SlidingWindowRateLimiter {
    private timestamps;
    private readonly maxRequests;
    private readonly windowMs;
    constructor(options: RateLimitOptions);
    acquire(): Promise<void>;
    getRemainingRequests(): number;
}

type CircuitState = 'closed' | 'open' | 'half-open';
interface CircuitBreakerOptions {
    failureThreshold?: number;
    successThreshold?: number;
    recoveryTimeMs?: number;
    onStateChange?: (from: CircuitState, to: CircuitState) => void;
    onFailure?: (error: Error, failures: number) => void;
    onSuccess?: () => void;
}
interface CircuitBreakerStats {
    state: CircuitState;
    failures: number;
    successes: number;
    totalRequests: number;
    lastFailureTime?: Date;
    lastStateChangeTime: Date;
}
declare class CircuitBreaker {
    private state;
    private failures;
    private successes;
    private totalRequests;
    private lastFailureTime?;
    private lastStateChangeTime;
    private readonly failureThreshold;
    private readonly successThreshold;
    private readonly recoveryTimeMs;
    private readonly onStateChange?;
    private readonly onFailure?;
    private readonly onSuccess?;
    constructor(options?: CircuitBreakerOptions);
    execute<T>(fn: () => Promise<T>): Promise<T>;
    private recordSuccess;
    private recordFailure;
    private transitionTo;
    private canAttemptReset;
    getState(): CircuitState;
    getStats(): CircuitBreakerStats;
    reset(): void;
    isOpen(): boolean;
    isClosed(): boolean;
}

interface CacheOptions {
    ttl: number;
    maxSize?: number;
    onHit?: (key: string) => void;
    onMiss?: (key: string) => void;
    onEvict?: (key: string) => void;
}
declare class CacheLayer {
    private store;
    private readonly ttlMs;
    private readonly maxSize;
    private readonly onHit?;
    private readonly onMiss?;
    private readonly onEvict?;
    private totalHits;
    private totalMisses;
    private totalSets;
    private totalEvictions;
    constructor(options: CacheOptions);
    get<T>(key: string): T | null;
    set<T>(key: string, data: T, ttlSeconds?: number): void;
    getOrSet<T>(key: string, fetchFn: () => Promise<T>, ttlSeconds?: number): Promise<T>;
    delete(key: string): boolean;
    clear(): void;
    clearByPrefix(prefix: string): number;
    has(key: string): boolean;
    private evictLRU;
    cleanup(): number;
    getStats(): {
        size: number;
        maxSize: number;
        totalHits: number;
        totalMisses: number;
        totalSets: number;
        totalEvictions: number;
        hitRate: string;
    };
}

declare enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
    SILENT = 4
}
interface LogEntry {
    level: LogLevel;
    message: string;
    timestamp: Date;
    connector?: string;
    meta?: unknown;
    traceId?: string;
}
interface LoggerOptions {
    level?: LogLevel;
    connector?: string;
    enableConsole?: boolean;
    enableJson?: boolean;
    onLog?: (entry: LogEntry) => void;
}
declare class Logger {
    private level;
    private connector?;
    private enableConsole;
    private enableJson;
    private onLog?;
    private logs;
    constructor(options?: LoggerOptions);
    private log;
    private printToConsole;
    debug(message: string, meta?: unknown, traceId?: string): void;
    info(message: string, meta?: unknown, traceId?: string): void;
    warn(message: string, meta?: unknown, traceId?: string): void;
    error(message: string, meta?: unknown, traceId?: string): void;
    child(connector: string): Logger;
    getLogs(level?: LogLevel): LogEntry[];
    clearLogs(): void;
    setLevel(level: LogLevel): void;
    getStats(): {
        total: number;
        debug: number;
        info: number;
        warn: number;
        error: number;
    };
}
declare const logger: Logger;

interface SpanOptions {
    name: string;
    connector?: string;
    method?: string;
    url?: string;
    attributes?: Record<string, string | number | boolean>;
}
interface Span {
    spanId: string;
    traceId: string;
    name: string;
    startTime: Date;
    endTime?: Date;
    duration?: number;
    status: 'ok' | 'error' | 'unset';
    attributes: Record<string, string | number | boolean>;
    events: SpanEvent[];
    error?: Error;
}
interface SpanEvent {
    name: string;
    timestamp: Date;
    attributes?: Record<string, string | number | boolean>;
}
interface TelemetryOptions {
    serviceName?: string;
    serviceVersion?: string;
    enabled?: boolean;
    onSpanEnd?: (span: Span) => void;
    exportUrl?: string;
}
declare class Tracer {
    private spans;
    private readonly serviceName;
    private readonly serviceVersion;
    private readonly enabled;
    private readonly onSpanEnd?;
    constructor(options?: TelemetryOptions);
    startSpan(options: SpanOptions): string;
    endSpan(spanId: string, error?: Error): void;
    addEvent(spanId: string, name: string, attributes?: Record<string, string | number | boolean>): void;
    setAttribute(spanId: string, key: string, value: string | number | boolean): void;
    trace<T>(options: SpanOptions, fn: (spanId: string) => Promise<T>): Promise<T>;
    getActiveSpans(): Span[];
    private generateId;
    isEnabled(): boolean;
}
declare const tracer: Tracer;

type AuditAction = 'connector.connect' | 'connector.disconnect' | 'data.fetch' | 'data.create' | 'data.update' | 'data.delete' | 'auth.login' | 'auth.logout' | 'auth.failed' | 'scan.launch' | 'scan.cancel' | 'threat.mitigate' | 'policy.change' | 'deployment.create' | 'deployment.cancel';
type AuditStatus = 'success' | 'failure' | 'pending';
interface AuditEntry {
    id: string;
    action: AuditAction;
    connector: string;
    status: AuditStatus;
    timestamp: Date;
    duration?: number;
    userId?: string;
    resourceId?: string;
    resourceType?: string;
    details?: Record<string, unknown>;
    error?: string;
    ipAddress?: string;
}
interface AuditLoggerOptions {
    enabled?: boolean;
    maxEntries?: number;
    onEntry?: (entry: AuditEntry) => void;
    storage?: 'memory' | 'custom';
}
declare class AuditLogger {
    private entries;
    private readonly enabled;
    private readonly maxEntries;
    private readonly onEntry?;
    constructor(options?: AuditLoggerOptions);
    log(entry: Omit<AuditEntry, 'id' | 'timestamp'>): AuditEntry;
    logSuccess(action: AuditAction, connector: string, details?: Record<string, unknown>, duration?: number): AuditEntry;
    logFailure(action: AuditAction, connector: string, error: string, details?: Record<string, unknown>): AuditEntry;
    logDataFetch(connector: string, resourceType: string, resourceId?: string, duration?: number): AuditEntry;
    getEntries(filter?: {
        connector?: string;
        action?: AuditAction;
        status?: AuditStatus;
        from?: Date;
        to?: Date;
        limit?: number;
    }): AuditEntry[];
    getFailures(connector?: string): AuditEntry[];
    getRecentEntries(limit?: number): AuditEntry[];
    getStats(connector?: string): {
        total: number;
        success: number;
        failure: number;
        successRate: string;
        avgDurationMs: number;
    };
    exportAsJson(): string;
    exportAsCsv(): string;
    clear(): void;
    private generateId;
}
declare const auditLogger: AuditLogger;

interface NormalizationResult<T> {
    data: T[];
    total: number;
    sources: string[];
    normalizedAt: Date;
    errors: NormalizationError[];
}
interface NormalizationError {
    source: string;
    message: string;
    raw?: unknown;
}
type UnifiedSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
interface SeverityMapping {
    [key: string]: UnifiedSeverity;
}
declare class NormalizationEngine {
    normalizeVulnerabilities(sources: Array<{
        connector: string;
        data: unknown[];
        mapper: (item: unknown) => NormalizedVulnerability | null;
    }>): NormalizationResult<NormalizedVulnerability>;
    normalizeAssets(sources: Array<{
        connector: string;
        data: unknown[];
        mapper: (item: unknown) => NormalizedAsset | null;
    }>): NormalizationResult<NormalizedAsset>;
    normalizeThreats(sources: Array<{
        connector: string;
        data: unknown[];
        mapper: (item: unknown) => NormalizedThreat | null;
    }>): NormalizationResult<NormalizedThreat>;
    private deduplicateVulnerabilities;
    private deduplicateAssets;
    private severityScore;
    mapSeverity(value: string, mapping: SeverityMapping): UnifiedSeverity;
    sortBySeverity<T extends {
        severity: UnifiedSeverity;
    }>(items: T[], order?: 'asc' | 'desc'): T[];
    filterBySeverity<T extends {
        severity: UnifiedSeverity;
    }>(items: T[], minSeverity: UnifiedSeverity): T[];
    getSeverityStats<T extends {
        severity: UnifiedSeverity;
    }>(items: T[]): Record<UnifiedSeverity, number>;
}
declare const normalizationEngine: NormalizationEngine;

declare const NormalizedVulnerabilitySchema: z.ZodObject<{
    id: z.ZodString;
    title: z.ZodString;
    severity: z.ZodEnum<{
        info: "info";
        critical: "critical";
        high: "high";
        medium: "medium";
        low: "low";
    }>;
    cvss: z.ZodOptional<z.ZodNumber>;
    cve: z.ZodOptional<z.ZodString>;
    affectedAsset: z.ZodString;
    source: z.ZodString;
    detectedAt: z.ZodDate;
    raw: z.ZodOptional<z.ZodUnknown>;
}, z.core.$strip>;
type ValidatedVulnerability = z.infer<typeof NormalizedVulnerabilitySchema>;
interface ValidationResult<T> {
    valid: T[];
    invalid: Array<{
        data: unknown;
        errors: string[];
    }>;
}
declare function validateVulnerabilities(items: unknown[]): ValidationResult<ValidatedVulnerability>;
declare function cvssToSeverity(cvss: number): 'critical' | 'high' | 'medium' | 'low' | 'info';

declare const NormalizedAssetSchema: z.ZodObject<{
    id: z.ZodString;
    hostname: z.ZodString;
    ipAddress: z.ZodString;
    os: z.ZodOptional<z.ZodString>;
    type: z.ZodEnum<{
        server: "server";
        workstation: "workstation";
        network: "network";
        cloud: "cloud";
        unknown: "unknown";
    }>;
    source: z.ZodString;
    lastSeen: z.ZodDate;
    raw: z.ZodOptional<z.ZodUnknown>;
}, z.core.$strip>;
type ValidatedAsset = z.infer<typeof NormalizedAssetSchema>;
interface AssetValidationResult {
    valid: ValidatedAsset[];
    invalid: Array<{
        data: unknown;
        errors: string[];
    }>;
}
declare function validateAssets(items: unknown[]): AssetValidationResult;
declare function detectAssetType(hostname: string, os?: string): 'server' | 'workstation' | 'network' | 'cloud' | 'unknown';
declare function isPrivateIP(ip: string): boolean;

interface StreamOptions {
    batchSize?: number;
    intervalMs?: number;
    maxItems?: number;
    onError?: (error: Error) => void;
}
interface StreamBatch<T> {
    items: T[];
    batchNumber: number;
    isLast: boolean;
    timestamp: Date;
}
declare class StreamManager extends EventEmitter {
    private activeStreams;
    createStream<T>(fetchFn: (page: number, limit: number) => Promise<{
        data: T[];
        hasMore: boolean;
    }>, options?: StreamOptions): AsyncGenerator<StreamBatch<T>>;
    startPolling<T>(streamId: string, fetchFn: () => Promise<T[]>, onData: (items: T[]) => void, options?: {
        intervalMs?: number;
        onError?: (error: Error) => void;
    }): Promise<void>;
    stopPolling(streamId: string): void;
    stopAllStreams(): void;
    processBatches<T, R>(items: T[], processFn: (batch: T[]) => Promise<R[]>, batchSize?: number): Promise<R[]>;
    getActiveStreams(): string[];
    private sleep;
}

interface VaultConfig {
    vaultUrl: string;
    token: string;
    namespace?: string;
    timeout?: number;
}
interface VaultSecret {
    path: string;
    data: Record<string, string>;
    version?: number;
    createdAt?: Date;
    expiresAt?: Date;
}
interface VaultAuthResponse {
    token: string;
    leaseDuration: number;
    renewable: boolean;
}
declare class VaultHandler {
    private client;
    private token;
    constructor(config: VaultConfig);
    readSecret(path: string): Promise<VaultSecret>;
    writeSecret(path: string, data: Record<string, string>): Promise<void>;
    deleteSecret(path: string): Promise<void>;
    listSecrets(path: string): Promise<string[]>;
    getConnectorCredentials(connectorName: string): Promise<Record<string, string>>;
    healthCheck(): Promise<boolean>;
    renewToken(): Promise<VaultAuthResponse>;
}

interface ConnectorEnvMap {
    qualys: {
        baseUrl: string;
        username: string;
        password: string;
    };
    sentinelone: {
        baseUrl: string;
        apiToken: string;
    };
    checkpoint: {
        baseUrl: string;
        username: string;
        password: string;
        domain?: string;
    };
    manageengine: {
        baseUrl: string;
        clientId: string;
        clientSecret: string;
        refreshToken: string;
    };
    jira: {
        baseUrl: string;
        email: string;
        apiToken: string;
    };
    zoho: {
        baseUrl: string;
        clientId: string;
        clientSecret: string;
        refreshToken: string;
    };
}
declare class EnvHandler {
    private prefix;
    constructor(prefix?: string);
    get(key: string, required?: boolean): string | undefined;
    getRequired(key: string): string;
    getQualysCredentials(): ConnectorEnvMap['qualys'];
    getSentinelOneCredentials(): ConnectorEnvMap['sentinelone'];
    getCheckpointCredentials(): ConnectorEnvMap['checkpoint'];
    getManageEngineCredentials(): ConnectorEnvMap['manageengine'];
    getJiraCredentials(): ConnectorEnvMap['jira'];
    getZohoCredentials(): ConnectorEnvMap['zoho'];
    validateConnector(connectorName: keyof ConnectorEnvMap): boolean;
    static getEnvExample(): string;
}
declare const envHandler: EnvHandler;

type WebhookEventType = 'threat.detected' | 'threat.resolved' | 'vulnerability.found' | 'vulnerability.fixed' | 'scan.completed' | 'agent.offline' | 'agent.online' | 'policy.changed' | 'patch.missing' | 'patch.installed';
interface WebhookEvent {
    id: string;
    type: WebhookEventType;
    connector: string;
    timestamp: Date;
    payload: Record<string, unknown>;
    signature?: string;
}
interface WebhookEndpoint {
    id: string;
    connector: string;
    secret?: string;
    enabled: boolean;
    events: WebhookEventType[];
    receivedCount: number;
    lastReceivedAt?: Date;
}
declare class WebhookManager extends EventEmitter {
    private handlers;
    private endpoints;
    private eventHistory;
    private readonly maxHistory;
    constructor(options?: {
        maxHistory?: number;
    });
    registerEndpoint(config: Omit<WebhookEndpoint, 'receivedCount'>): void;
    on(eventType: WebhookEventType | '*', handler: (event: WebhookEvent) => void): this;
    on(event: string | symbol, listener: (...args: any[]) => void): this;
    onConnector(connector: string, eventType: WebhookEventType | '*', handler: (event: WebhookEvent) => void | Promise<void>): void;
    processWebhook(endpointId: string, payload: Record<string, unknown>, signature?: string): Promise<{
        success: boolean;
        error?: string;
    }>;
    private dispatchEvent;
    private verifySignature;
    static generateSecret(): string;
    getHistory(filter?: {
        connector?: string;
        eventType?: WebhookEventType;
        limit?: number;
    }): WebhookEvent[];
    getStats(): {
        totalEvents: number;
        registeredEndpoints: number;
        registeredHandlers: number;
        byConnector: Record<string, number>;
        byType: Record<string, number>;
    };
    getEndpoints(): WebhookEndpoint[];
    private generateId;
}

interface MCPTool {
    name: string;
    description: string;
    inputSchema: {
        type: 'object';
        properties: Record<string, MCPToolProperty>;
        required?: string[];
    };
    handler: (input: Record<string, unknown>) => Promise<MCPToolResult>;
}
interface MCPToolProperty {
    type: 'string' | 'number' | 'boolean' | 'array' | 'object';
    description: string;
    enum?: string[];
    items?: {
        type: string;
    };
}
interface MCPToolResult {
    content: Array<{
        type: 'text' | 'json';
        text?: string;
        data?: unknown;
    }>;
    isError?: boolean;
}
interface MCPServerOptions {
    name?: string;
    version?: string;
    description?: string;
}
declare class MCPServer {
    private tools;
    private readonly name;
    private readonly version;
    private readonly description;
    constructor(options?: MCPServerOptions);
    registerTool(tool: MCPTool): void;
    registerConnectorTools(connectorName: string, methods: Array<{
        name: string;
        description: string;
        params?: Record<string, MCPToolProperty>;
        handler: (params: Record<string, unknown>) => Promise<unknown>;
    }>): void;
    executeTool(name: string, input: Record<string, unknown>): Promise<MCPToolResult>;
    listTools(): MCPTool[];
    getToolByName(name: string): MCPTool | undefined;
    getServerInfo(): {
        name: string;
        version: string;
        description: string;
        toolCount: number;
    };
    generateManifest(): {
        schema_version: string;
        name_for_human: string;
        name_for_model: string;
        description_for_human: string;
        description_for_model: string;
        api: {
            type: string;
            version: string;
        };
        tools: {
            name: string;
            description: string;
            input_schema: {
                type: "object";
                properties: Record<string, MCPToolProperty>;
                required?: string[];
            };
        }[];
    };
}
declare function createQualysMCPTools(qualysConnector: {
    getAssets: (filter?: unknown) => Promise<unknown>;
    getVulnerabilities: (filter?: unknown) => Promise<unknown>;
    getCriticalVulnerabilities: () => Promise<unknown>;
    getScans: (filter?: unknown) => Promise<unknown>;
    healthCheck: () => Promise<unknown>;
}): ({
    name: string;
    description: string;
    params: {
        limit: {
            type: "number";
            description: string;
        };
        hostname: {
            type: "string";
            description: string;
        };
        severity?: undefined;
        status?: undefined;
    };
    handler: (params: Record<string, unknown>) => Promise<unknown>;
} | {
    name: string;
    description: string;
    params: {
        severity: {
            type: "array";
            description: string;
            items: {
                type: string;
            };
        };
        status: {
            type: "string";
            description: string;
        };
        limit?: undefined;
        hostname?: undefined;
    };
    handler: (params: Record<string, unknown>) => Promise<unknown>;
} | {
    name: string;
    description: string;
    handler: () => Promise<unknown>;
    params?: undefined;
})[];
declare function createSentinelOneMCPTools(s1Connector: {
    getAgents: (filter?: unknown) => Promise<unknown>;
    getThreats: (filter?: unknown) => Promise<unknown>;
    getCriticalThreats: () => Promise<unknown>;
    quarantineThreat: (id: string) => Promise<unknown>;
    healthCheck: () => Promise<unknown>;
}): ({
    name: string;
    description: string;
    params: {
        infected: {
            type: "boolean";
            description: string;
        };
        limit: {
            type: "number";
            description: string;
        };
        severity?: undefined;
        status?: undefined;
        threatId?: undefined;
    };
    handler: (params: Record<string, unknown>) => Promise<unknown>;
} | {
    name: string;
    description: string;
    params: {
        severity: {
            type: "string";
            description: string;
        };
        status: {
            type: "string";
            description: string;
        };
        infected?: undefined;
        limit?: undefined;
        threatId?: undefined;
    };
    handler: (params: Record<string, unknown>) => Promise<unknown>;
} | {
    name: string;
    description: string;
    params: {
        threatId: {
            type: "string";
            description: string;
        };
        infected?: undefined;
        limit?: undefined;
        severity?: undefined;
        status?: undefined;
    };
    handler: (params: Record<string, unknown>) => Promise<unknown>;
} | {
    name: string;
    description: string;
    handler: () => Promise<unknown>;
    params?: undefined;
})[];
declare const mcpServer: MCPServer;

interface LangChainToolSchema {
    name: string;
    description: string;
    schema: {
        type: 'object';
        properties: Record<string, {
            type: string;
            description: string;
            enum?: string[];
        }>;
        required?: string[];
    };
}
interface LangChainTool {
    name: string;
    description: string;
    schema: LangChainToolSchema['schema'];
    call: (input: string | Record<string, unknown>) => Promise<string>;
}
declare class LangChainAdapter {
    static createTool(options: {
        name: string;
        description: string;
        schema?: LangChainToolSchema['schema'];
        handler: (input: Record<string, unknown>) => Promise<unknown>;
    }): LangChainTool;
    static createQualysTools(qualysConnector: {
        getAssets: (filter?: unknown) => Promise<unknown>;
        getVulnerabilities: (filter?: unknown) => Promise<unknown>;
        getCriticalVulnerabilities: () => Promise<unknown>;
        getNormalizedVulnerabilities: (filter?: unknown) => Promise<unknown>;
        healthCheck: () => Promise<unknown>;
    }): LangChainTool[];
    static createSentinelOneTools(s1Connector: {
        getAgents: (filter?: unknown) => Promise<unknown>;
        getThreats: (filter?: unknown) => Promise<unknown>;
        getCriticalThreats: () => Promise<unknown>;
        getActiveThreatCount: () => Promise<unknown>;
        quarantineThreat: (id: string) => Promise<unknown>;
        killThreat: (id: string) => Promise<unknown>;
        getNormalizedThreats: (filter?: unknown) => Promise<unknown>;
        healthCheck: () => Promise<unknown>;
    }): LangChainTool[];
    static createJiraTools(jiraConnector: {
        getIssues: (filter?: unknown) => Promise<unknown>;
        createIssue: (request: unknown) => Promise<unknown>;
        createSecurityTicket: (projectKey: string, title: string, description: string, severity: string, source: string) => Promise<unknown>;
        addComment: (issueKey: string, body: string) => Promise<unknown>;
        transitionIssue: (issueKey: string, transitionId: string) => Promise<unknown>;
        healthCheck: () => Promise<unknown>;
    }): LangChainTool[];
    static createAllTools(connectors: {
        qualys?: Parameters<typeof LangChainAdapter.createQualysTools>[0];
        sentinelone?: Parameters<typeof LangChainAdapter.createSentinelOneTools>[0];
        jira?: Parameters<typeof LangChainAdapter.createJiraTools>[0];
    }): LangChainTool[];
}

interface VercelAITool {
    description: string;
    parameters: any;
    execute: (args: any) => Promise<any>;
}
type VercelAIToolSet = Record<string, VercelAITool>;
/**
 * Adapter for Vercel AI SDK (ai)
 */
declare class VercelAIAdapter {
    /**
     * Create a tool for Vercel AI SDK
     */
    static createTool(options: {
        description: string;
        parameters: any;
        execute: (args: any) => Promise<any>;
    }): VercelAITool;
    /**
     * Create a set of tools for a connector
     */
    static createToolkit(tools: VercelAIToolSet): VercelAIToolSet;
}

interface OpenAIAgentTool {
    type: 'function';
    function: {
        name: string;
        description: string;
        parameters: {
            type: 'object';
            properties: Record<string, OpenAIToolProperty>;
            required?: string[];
        };
        strict?: boolean;
    };
    execute: (params: Record<string, unknown>) => Promise<string>;
}
interface OpenAIToolProperty {
    type: 'string' | 'number' | 'boolean' | 'array' | 'object';
    description: string;
    enum?: string[];
    items?: {
        type: string;
    };
}
interface OpenAIAgentDefinition {
    name: string;
    instructions: string;
    tools: OpenAIAgentTool[];
    model?: string;
}
declare class OpenAIAgentsAdapter {
    static createTool(options: {
        name: string;
        description: string;
        parameters?: Record<string, OpenAIToolProperty>;
        required?: string[];
        strict?: boolean;
        execute: (params: Record<string, unknown>) => Promise<unknown>;
    }): OpenAIAgentTool;
    static createSecurityAnalystAgent(connectors: {
        qualys?: {
            getVulnerabilities: (filter?: unknown) => Promise<unknown>;
            getCriticalVulnerabilities: () => Promise<unknown>;
            getAssets: (filter?: unknown) => Promise<unknown>;
        };
        sentinelone?: {
            getThreats: (filter?: unknown) => Promise<unknown>;
            getCriticalThreats: () => Promise<unknown>;
            quarantineThreat: (id: string) => Promise<unknown>;
        };
        jira?: {
            createSecurityTicket: (projectKey: string, title: string, description: string, severity: string, source: string) => Promise<unknown>;
        };
    }): OpenAIAgentDefinition;
    static createComplianceAgent(connectors: {
        qualys?: {
            getComplianceControls: () => Promise<unknown>;
            getVulnerabilities: (filter?: unknown) => Promise<unknown>;
        };
        manageengine?: {
            getMissingPatches: () => Promise<unknown>;
            getCriticalPatches: () => Promise<unknown>;
        };
        jira?: {
            createSecurityTicket: (projectKey: string, title: string, description: string, severity: string, source: string) => Promise<unknown>;
        };
    }): OpenAIAgentDefinition;
    static toOpenAIFormat(tools: OpenAIAgentTool[]): Array<{
        type: 'function';
        function: OpenAIAgentTool['function'];
    }>;
}

type HITLActionType = 'threat.quarantine' | 'threat.kill' | 'threat.remediate' | 'policy.change' | 'policy.delete' | 'deployment.create' | 'deployment.cancel' | 'agent.disconnect' | 'rule.add' | 'rule.delete' | 'scan.launch';
type HITLStatus = 'pending' | 'approved' | 'rejected' | 'expired' | 'executing' | 'completed' | 'failed';
type HITLRiskLevel = 'low' | 'medium' | 'high' | 'critical';
interface HITLRequest {
    id: string;
    actionType: HITLActionType;
    connector: string;
    description: string;
    riskLevel: HITLRiskLevel;
    params: Record<string, unknown>;
    requestedBy: string;
    requestedAt: Date;
    expiresAt: Date;
    status: HITLStatus;
    approvedBy?: string;
    approvedAt?: Date;
    rejectedBy?: string;
    rejectedReason?: string;
    executedAt?: Date;
    result?: unknown;
    error?: string;
}
interface HITLManagerOptions {
    defaultTimeoutMs?: number;
    autoApproveRiskLevels?: HITLRiskLevel[];
    onApprovalRequired?: (request: HITLRequest) => void;
    onApproved?: (request: HITLRequest) => void;
    onRejected?: (request: HITLRequest) => void;
    onExpired?: (request: HITLRequest) => void;
    onCompleted?: (request: HITLRequest) => void;
}
declare class HITLManager {
    private requests;
    private handlers;
    private readonly defaultTimeoutMs;
    private readonly autoApproveRiskLevels;
    private readonly onApprovalRequired?;
    private readonly onApproved?;
    private readonly onRejected?;
    private readonly onExpired?;
    private readonly onCompleted?;
    constructor(options?: HITLManagerOptions);
    registerHandler(actionType: HITLActionType, handler: (params: Record<string, unknown>) => Promise<unknown>): void;
    requestApproval(options: {
        actionType: HITLActionType;
        connector: string;
        description: string;
        riskLevel: HITLRiskLevel;
        params: Record<string, unknown>;
        requestedBy: string;
        timeoutMs?: number;
    }): Promise<HITLRequest>;
    approve(requestId: string, approvedBy: string): Promise<HITLRequest>;
    reject(requestId: string, rejectedBy: string, reason: string): HITLRequest;
    private execute;
    waitForApproval(requestId: string, pollIntervalMs?: number): Promise<HITLRequest>;
    getPendingRequests(): HITLRequest[];
    getRequestById(id: string): HITLRequest | undefined;
    getRequestsByConnector(connector: string): HITLRequest[];
    getRequestsByStatus(status: HITLStatus): HITLRequest[];
    getStats(): {
        total: number;
        pending: number;
        approved: number;
        rejected: number;
        completed: number;
        failed: number;
        expired: number;
    };
    static getRiskLevel(actionType: HITLActionType): HITLRiskLevel;
    private generateId;
}
declare const hitlManager: HITLManager;

type WorkflowStepType = 'fetch' | 'analyze' | 'filter' | 'transform' | 'action' | 'notify' | 'condition' | 'parallel';
type WorkflowStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
interface WorkflowStep {
    id: string;
    name: string;
    type: WorkflowStepType;
    connector?: string;
    method?: string;
    params?: Record<string, unknown>;
    condition?: (context: WorkflowContext) => boolean;
    transform?: (data: unknown, context: WorkflowContext) => unknown;
    onSuccess?: (result: unknown, context: WorkflowContext) => void;
    onError?: (error: Error, context: WorkflowContext) => void;
    dependsOn?: string[];
    retries?: number;
    timeoutMs?: number;
}
interface WorkflowContext {
    workflowId: string;
    results: Map<string, unknown>;
    errors: Map<string, Error>;
    startedAt: Date;
    metadata: Record<string, unknown>;
}
interface WorkflowDefinition {
    id: string;
    name: string;
    description?: string;
    steps: WorkflowStep[];
    onComplete?: (context: WorkflowContext) => void;
    onError?: (error: Error, context: WorkflowContext) => void;
}
interface WorkflowExecution {
    executionId: string;
    workflowId: string;
    status: WorkflowStatus;
    startedAt: Date;
    completedAt?: Date;
    context: WorkflowContext;
    stepResults: Map<string, StepResult>;
    error?: string;
}
interface StepResult {
    stepId: string;
    status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
    startedAt?: Date;
    completedAt?: Date;
    data?: unknown;
    error?: string;
    retryCount: number;
}
declare class AgentOrchestrator {
    private workflows;
    private executions;
    private connectors;
    registerConnector(name: string, connector: Record<string, (...args: unknown[]) => Promise<unknown>>): void;
    registerWorkflow(workflow: WorkflowDefinition): void;
    executeWorkflow(workflowId: string, metadata?: Record<string, unknown>): Promise<WorkflowExecution>;
    private executeSteps;
    private executeStep;
    private executeConnectorStep;
    private executeFilterStep;
    private executeParallelStep;
    private resolveParams;
    createVulnerabilityResponseWorkflow(): WorkflowDefinition;
    createThreatResponseWorkflow(): WorkflowDefinition;
    getExecution(executionId: string): WorkflowExecution | undefined;
    getExecutionsByWorkflow(workflowId: string): WorkflowExecution[];
    getStats(): {
        totalExecutions: number;
        completed: number;
        failed: number;
        running: number;
        registeredWorkflows: number;
        registeredConnectors: number;
    };
    private sleep;
    private generateId;
}
declare const orchestrator: AgentOrchestrator;

interface SemanticDocument {
    id: string;
    content: string;
    metadata: {
        connector: string;
        type: 'vulnerability' | 'asset' | 'threat' | 'log' | 'policy';
        severity?: string;
        source?: string;
        timestamp?: Date;
        [key: string]: unknown;
    };
    embedding?: number[];
}
interface SemanticSearchResult {
    document: SemanticDocument;
    score: number;
    highlights?: string[];
}
interface SemanticSearchOptions {
    topK?: number;
    minScore?: number;
    connector?: string;
    type?: SemanticDocument['metadata']['type'];
    filters?: Record<string, unknown>;
}
interface EmbeddingProvider {
    embed: (text: string) => Promise<number[]>;
    embedBatch: (texts: string[]) => Promise<number[][]>;
}
declare class SemanticSearch {
    private documents;
    private tfidfIndex;
    private embeddingProvider?;
    private readonly useVectorSearch;
    constructor(options?: {
        embeddingProvider?: EmbeddingProvider;
        useVectorSearch?: boolean;
    });
    indexDocument(doc: SemanticDocument): Promise<void>;
    indexBatch(docs: SemanticDocument[]): Promise<void>;
    search(query: string, options?: SemanticSearchOptions): Promise<SemanticSearchResult[]>;
    private keywordSearch;
    private vectorSearch;
    indexVulnerabilities(vulnerabilities: Array<{
        id: string;
        title: string;
        severity: string;
        cve?: string;
        affectedAsset: string;
        source: string;
    }>): void;
    indexThreats(threats: Array<{
        id: string;
        name: string;
        severity: string;
        affectedAsset: string;
        source: string;
    }>): void;
    indexAssets(assets: Array<{
        id: string;
        hostname: string;
        ipAddress: string;
        os?: string;
        source: string;
    }>): void;
    findCriticalThreats(): Promise<SemanticSearchResult[]>;
    findVulnerableAssets(hostname: string): Promise<SemanticSearchResult[]>;
    findByKeyword(keyword: string): Promise<SemanticSearchResult[]>;
    private extractHighlights;
    getStats(): {
        totalDocuments: number;
        byConnector: Record<string, number>;
        byType: Record<string, number>;
        vectorSearchEnabled: boolean;
    };
    clearIndex(): void;
}
declare const semanticSearch: SemanticSearch;

interface AgentWorkflowOptions {
    hitlManager?: HITLManager;
    orchestrator?: AgentOrchestrator;
    semanticSearch?: SemanticSearch;
    auditLogger?: AuditLogger;
    requireApproval?: boolean;
    agentName?: string;
}
interface WorkflowResult {
    workflowName: string;
    status: 'success' | 'failed' | 'pending_approval';
    startedAt: Date;
    completedAt?: Date;
    steps: Array<{
        name: string;
        status: 'success' | 'failed' | 'skipped';
        data?: unknown;
        error?: string;
    }>;
    summary?: string;
    requiresAction?: string[];
}
declare class AgentWorkflow {
    private hitlManager?;
    private orchestrator?;
    private semanticSearch?;
    private auditLogger?;
    private requireApproval;
    private agentName;
    constructor(options?: AgentWorkflowOptions);
    runSecurityPostureAssessment(connectors: {
        qualys?: {
            getCriticalVulnerabilities: () => Promise<unknown>;
            getAssets: () => Promise<unknown>;
            healthCheck: () => Promise<unknown>;
        };
        sentinelone?: {
            getCriticalThreats: () => Promise<unknown>;
            getInfectedAgents: () => Promise<unknown>;
            healthCheck: () => Promise<unknown>;
        };
        checkpoint?: {
            getGateways: () => Promise<unknown>;
            healthCheck: () => Promise<unknown>;
        };
    }): Promise<WorkflowResult>;
    runThreatResponse(threatId: string, connectors: {
        sentinelone: {
            getThreats: (filter: unknown) => Promise<unknown>;
            quarantineThreat: (id: string) => Promise<unknown>;
            killThreat: (id: string) => Promise<unknown>;
        };
        jira?: {
            createSecurityTicket: (projectKey: string, title: string, description: string, severity: string, source: string) => Promise<unknown>;
        };
    }, jiraProjectKey?: string): Promise<WorkflowResult>;
    runPatchComplianceCheck(connectors: {
        manageengine: {
            getCriticalPatches: () => Promise<unknown>;
            getMissingPatches: () => Promise<unknown>;
            getComputers: () => Promise<unknown>;
        };
        jira?: {
            createSecurityTicket: (projectKey: string, title: string, description: string, severity: string, source: string) => Promise<unknown>;
        };
    }): Promise<WorkflowResult>;
    runNLQuery(query: string, options?: {
        topK?: number;
        type?: string;
    }): Promise<WorkflowResult>;
    private generateAssessmentSummary;
}
declare const agentWorkflow: AgentWorkflow;

declare const SDK_VERSION = "0.1.0";
declare const SDK_NAME = "@skillmine/connectors-sdk";

export { APIError, AgentOrchestrator, AgentWorkflow, type ApiKeyAuthConfig, type AuditAction, type AuditEntry, AuditLogger, type AuditStatus, type AuthConfig, type AuthResult, AuthType, AuthenticationError, BaseConnector, type BasicAuthConfig, type BearerAuthConfig, CacheLayer, type CacheOptions, type CheckpointConfig, CheckpointConnector, type CheckpointGateway, type CheckpointGatewayStatus, type CheckpointGroup, type CheckpointHost, type CheckpointHostFilter, type CheckpointLog, type CheckpointLogFilter, type CheckpointNetwork, type CheckpointPolicy, type CheckpointRule, type CheckpointRuleAction, type CheckpointRuleFilter, type CheckpointSession, type CheckpointThreat, type CheckpointThreatSeverity, CircuitBreaker, CircuitBreakerOpenError, type CircuitBreakerOptions, type CircuitBreakerStats, type CircuitState, type ComputerStatus, ConfigurationError, ConnectionError, type ConnectorConfig, ConnectorEvent, ConnectorRegistry, type ConnectorResponse, ConnectorStatus, type DeploymentStatus, DuplicatePluginError, EnvHandler, HITLManager, type HITLRequest, type HITLRiskLevel, type HITLStatus, type HealthCheckResult, InvalidCredentialsError, type JiraComment, type JiraConfig, JiraConnector, type JiraCreateIssueRequest, type JiraIssue, type JiraIssueFilter, type JiraIssueListResponse, type JiraIssuePriority, type JiraIssueStatus, type JiraIssueType, type JiraProject, type JiraSprint, type JiraSprintState, type JiraTransition, type JiraUpdateIssueRequest, type JiraUser, LangChainAdapter, type LangChainTool, type LogEntry, LogLevel, Logger, type LoggerOptions, MCPServer, type MCPTool, type MCPToolResult, type ManageEngineComputer, type ManageEngineComputerFilter, type ManageEngineComputerListResponse, type ManageEngineConfig, ManageEngineConnector, type ManageEngineDeployment, type ManageEngineDeploymentFilter, type ManageEnginePatch, type ManageEnginePatchFilter, type ManageEnginePatchListResponse, type ManageEngineVulnerability, type MitigationAction, type MitigationRequest, type MitigationResponse, NormalizationEngine, type NormalizationResult, type NormalizedAsset, type NormalizedThreat, type NormalizedVulnerability, NotFoundError, type OAuth2Config, type OAuth2TokenRequest, type OpenAIAgentDefinition, type OpenAIAgentTool, OpenAIAgentsAdapter, type PaginatedResponse, type PaginationOptions, type PatchSeverity, type PatchStatus, PluginNotFoundError, type QualysAsset, type QualysAssetFilter, type QualysAssetListResponse, type QualysComplianceControl, type QualysConfig, QualysConnector, type QualysReport, type QualysScan, type QualysScanFilter, type QualysScanListResponse, type QualysScanStatus, type QualysSeverity, type QualysVulnFilter, type QualysVulnListResponse, type QualysVulnerability, RateLimitError, type RateLimitOptions, RateLimiter, RetryHandler, type RetryOptions, SDKError, SDK_NAME, SDK_VERSION, type SemanticDocument, SemanticSearch, type SemanticSearchResult, type SentinelOneActivity, type SentinelOneAgent, type SentinelOneAgentFilter, type SentinelOneAgentListResponse, type SentinelOneAgentStatus, type SentinelOneConfidenceLevel, type SentinelOneConfig, SentinelOneConnector, type SentinelOneGroup, type SentinelOneSite, type SentinelOneThreat, type SentinelOneThreatFilter, type SentinelOneThreatListResponse, type SentinelOneThreatStatus, SlidingWindowRateLimiter, type Span, type SpanOptions, StreamManager, type TelemetryOptions, TimeoutError, TokenExpiredError, type TokenResponse, Tracer, ValidationError, type VaultAuthConfig, VaultHandler, VercelAIAdapter, type VercelAITool, type VercelAIToolSet, WebhookManager, type WorkflowDefinition, type WorkflowExecution, type WorkflowResult, type ZohoAccount, type ZohoConfig, ZohoConnector, type ZohoContact, type ZohoContactFilter, type ZohoContactListResponse, type ZohoDeal, type ZohoDealFilter, type ZohoDealStage, type ZohoLead, type ZohoLeadFilter, type ZohoLeadStatus, type ZohoSearchResponse, type ZohoTask, type ZohoTaskStatus, agentWorkflow, auditLogger, createQualysMCPTools, createSentinelOneMCPTools, cvssToSeverity, detectAssetType, envHandler, hitlManager, isPrivateIP, logger, mcpServer, normalizationEngine, orchestrator, registry, semanticSearch, tracer, validateAssets, validateVulnerabilities, withRetry };
