// ============================================
// ASSET SCHEMA - Skillmine Connectors SDK
// ============================================

import { z } from 'zod'

// ============================================
// Zod Schema - Runtime Validation
// ============================================

export const AssetTypeSchema = z.enum([
    'server',
    'workstation',
    'network',
    'cloud',
    'unknown',
])

export const NormalizedAssetSchema = z.object({
    id: z.string().min(1),
    hostname: z.string().min(1),
    ipAddress: z.string().refine(isValidIP, { message: "Invalid IP address" }),
    os: z.string().optional(),
    type: AssetTypeSchema,
    source: z.string().min(1),
    lastSeen: z.date(),
    raw: z.unknown().optional(),
})

export type ValidatedAsset = z.infer<typeof NormalizedAssetSchema>

// ============================================
// Validation Helper
// ============================================

export interface AssetValidationResult {
    valid: ValidatedAsset[]
    invalid: Array<{ data: unknown; errors: string[] }>
}

export function validateAssets(
    items: unknown[],
): AssetValidationResult {
    const valid: ValidatedAsset[] = []
    const invalid: Array<{ data: unknown; errors: string[] }> = []

    for (const item of items) {
        const result = NormalizedAssetSchema.safeParse(item)

        if (result.success) {
            valid.push(result.data)
        } else {
            invalid.push({
                data: item,
                errors: result.error.issues.map(
                    (e) => `${e.path.join('.')}: ${e.message}`,
                ),
            })
        }
    }

    return { valid, invalid }
}

// ============================================
// Asset Type Detection
// ============================================

export function detectAssetType(
    hostname: string,
    os?: string,
): 'server' | 'workstation' | 'network' | 'cloud' | 'unknown' {
    const h = hostname.toLowerCase()
    const o = os?.toLowerCase() ?? ''

    if (
        h.includes('srv') ||
        h.includes('server') ||
        o.includes('server') ||
        o.includes('ubuntu') ||
        o.includes('centos') ||
        o.includes('rhel')
    ) return 'server'

    if (
        h.includes('ws') ||
        h.includes('desktop') ||
        h.includes('laptop') ||
        o.includes('windows 10') ||
        o.includes('windows 11') ||
        o.includes('macos')
    ) return 'workstation'

    if (
        h.includes('fw') ||
        h.includes('router') ||
        h.includes('switch') ||
        h.includes('firewall')
    ) return 'network'

    if (
        h.includes('aws') ||
        h.includes('azure') ||
        h.includes('gcp') ||
        h.includes('cloud')
    ) return 'cloud'

    return 'unknown'
}

// ============================================
// IP Address Helpers
// ============================================

export function isPrivateIP(ip: string): boolean {
    const privateRanges = [
        /^10\./,
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
        /^192\.168\./,
        /^127\./,
    ]
    return privateRanges.some((range) => range.test(ip))
}

export function isValidIP(ip: string): boolean {
    const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/
    const ipv6 = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/
    return ipv4.test(ip) || ipv6.test(ip)
}