const { z } = require('zod')

const VulnerabilitySchema = z.object({
  id: z.string(),
  qid: z.number(),
  title: z.string(),
  severity: z.number().min(1).max(5),
  cvss: z.number().min(0).max(10),
  cve: z.string().optional(),
  ip: z.string().optional(),
  hostname: z.string().optional(),
  operatingSystem: z.string().optional(),
  lastFound: z.string().optional(),
  status: z.string().optional(),
  category: z.string().optional(),
  solution: z.string().optional(),
})

const VulnerabilityListSchema = z.object({
  vulnerabilities: z.array(VulnerabilitySchema),
  count: z.number(),
  warnings: z.array(z.string()).optional(),
})

const AssetSchema = z.object({
  id: z.string(),
  hostname: z.string(),
  ip: z.string(),
  operatingSystem: z.string().optional(),
  lastSeen: z.string(),
  source: z.string(),
})

const ThreatSchema = z.object({
  id: z.string(),
  name: z.string(),
  threatType: z.string(),
  severity: z.enum(['critical', 'high', 'medium', 'low']),
  status: z.enum(['active', 'quarantined', 'resolved']),
  filePath: z.string().optional(),
  md5: z.string().optional(),
  createdAt: z.string(),
  agent: z.object({
    id: z.string(),
    hostname: z.string(),
    ip: z.string(),
    os: z.string(),
  }),
  mitigationStatus: z.string().optional(),
})

const JiraIssueSchema = z.object({
  key: z.string(),
  summary: z.string(),
  priority: z.string(),
  status: z.string(),
  assignee: z.string().optional(),
  created: z.string().optional(),
  labels: z.array(z.string()).optional(),
})

const TenableVulnerabilitySchema = z.object({
  pluginId: z.number(),
  name: z.string(),
  severity: z.number().min(0).max(4),
  cvss: z.number().optional(),
  description: z.string().optional(),
  solution: z.string().optional(),
  host: z.string().optional(),
  protocol: z.string().optional(),
})

function validateVulnerability(data) {
  return VulnerabilitySchema.safeParse(data)
}

function validateThreat(data) {
  return ThreatSchema.safeParse(data)
}

function validateJiraIssue(data) {
  return JiraIssueSchema.safeParse(data)
}

function validateTenableVuln(data) {
  return TenableVulnerabilitySchema.safeParse(data)
}

function validateBatch(schema, data) {
  const valid = []
  const invalid = []

  data.forEach((item, index) => {
    const result = schema.safeParse(item)
    if (result.success) {
      valid.push(result.data)
    } else {
      invalid.push({ index, error: result.error })
    }
  })

  return { valid, invalid }
}

module.exports = {
  VulnerabilitySchema,
  VulnerabilityListSchema,
  AssetSchema,
  ThreatSchema,
  JiraIssueSchema,
  TenableVulnerabilitySchema,
  validateVulnerability,
  validateThreat,
  validateJiraIssue,
  validateTenableVuln,
  validateBatch,
}