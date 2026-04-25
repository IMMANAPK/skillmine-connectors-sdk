const express = require('express')
const { injectError } = require('../mocks/errors/index.cjs')

const DEFAULT_MOCK_CONFIG = {
  port: 3100,
  host: 'localhost',
  mode: 'mock',
  responseDelay: 50,
  errorInjection: {
    enabled: false,
  },
}

const app = express()
app.use(express.json())

let config = { ...DEFAULT_MOCK_CONFIG }

function configureMockServer(newConfig) {
  config = { ...config, ...newConfig }
}

function getMockConfig() {
  return { ...config }
}

app.get('/', (req, res) => {
  res.json({
    service: 'Complyment Connectors SDK Mock Server',
    version: '1.0.0',
    status: 'running',
    endpoints: [
      'GET /api/health',
      'GET /api/:connector/:resource',
      'POST /api/:connector/:action',
    ],
    connectors: ['qualys', 'sentinelone', 'jira', 'tenable-io', 'tenable-sc', 'checkpoint'],
  })
})

app.use((req, res, next) => {
  if (config.responseDelay > 0) {
    setTimeout(next, config.responseDelay)
  } else {
    next()
  }
})

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    mode: config.mode,
    errorInjection: config.errorInjection.enabled,
  })
})

app.post('/api/:connector/:action', (req, res) => {
  const { connector, action } = req.params
  const error = injectError()
  if (error) {
    res.status(error.statusCode)
    if (error.headers) {
      Object.entries(error.headers).forEach(([key, value]) => {
        res.setHeader(key, value)
      })
    }
    res.json({ error: error.message, type: error.type })
    return
  }

  const mockResponse = getMockResponse(connector, action, req.body)
  res.json(mockResponse)
})

app.get('/api/:connector/:resource', (req, res) => {
  const { connector, resource } = req.params
  const error = injectError()
  if (error) {
    res.status(error.statusCode)
    res.json({ error: error.message, type: error.type })
    return
  }

  const mockResponse = getMockResponse(connector, resource, req.query)
  res.json(mockResponse)
})

function getMockResponse(connector, action, params) {
  const key = `${connector}_${action}`

  // Responses aligned with Zod schemas in validation.cjs
  const responses = {
    // Matches VulnerabilityListSchema: { vulnerabilities, count, warnings? }
    qualys_vulns: {
      vulnerabilities: [
        {
          id: 'vuln-001',
          qid: 12345,
          title: 'SQL Injection in Login Form',
          severity: 5,
          cvss: 9.8,
          cve: 'CVE-2024-12345',
          ip: '192.168.1.10',
          hostname: 'web-server-01',
          operatingSystem: 'Ubuntu 22.04 LTS',
          lastFound: '2024-03-15T10:30:00Z',
          status: 'Active',
          category: 'Injection',
          solution: 'Update to latest version',
        },
        {
          id: 'vuln-002',
          qid: 12346,
          title: 'Cross-Site Scripting (XSS)',
          severity: 4,
          cvss: 7.5,
          cve: 'CVE-2024-12346',
          ip: '192.168.1.11',
          hostname: 'web-server-02',
          operatingSystem: 'Windows Server 2022',
          lastFound: '2024-03-14T08:15:00Z',
          status: 'Active',
          category: 'XSS',
          solution: 'Sanitize user inputs',
        },
      ],
      count: 2,
      warnings: [],
    },
    // Matches AssetSchema: { id, hostname, ip, operatingSystem?, lastSeen, source }
    qualys_assets: {
      assets: [
        {
          id: 'asset-001',
          hostname: 'web-server-01',
          ip: '192.168.1.10',
          operatingSystem: 'Ubuntu 22.04 LTS',
          lastSeen: '2024-03-20T12:00:00Z',
          source: 'qualys',
        },
        {
          id: 'asset-002',
          hostname: 'db-server-01',
          ip: '192.168.1.20',
          operatingSystem: 'CentOS 8',
          lastSeen: '2024-03-20T12:00:00Z',
          source: 'qualys',
        },
      ],
      count: 2,
    },
    // Matches ThreatSchema: { id, name, threatType, severity, status, filePath?, md5?, createdAt, agent, mitigationStatus? }
    sentinelone_threats: {
      threats: [
        {
          id: 'threat-001',
          name: 'Trojan.GenericKD.46789',
          threatType: 'Trojan',
          severity: 'critical',
          status: 'active',
          filePath: 'C:\\Windows\\System32\\malware.dll',
          md5: 'd41d8cd98f00b204e9800998ecf8427e',
          createdAt: '2024-03-20T14:30:00Z',
          agent: {
            id: 'agent-001',
            hostname: 'DESKTOP-XYZ',
            ip: '192.168.1.50',
            os: 'Windows 11 Pro',
          },
          mitigationStatus: 'not mitigated',
        },
        {
          id: 'threat-002',
          name: 'Ransomware.Cryptor.A',
          threatType: 'Ransomware',
          severity: 'critical',
          status: 'active',
          filePath: 'C:\\Users\\admin\\Documents\\encrypted.txt',
          md5: '5d41402abc4b2a76b9719d911017c592',
          createdAt: '2024-03-19T09:15:00Z',
          agent: {
            id: 'agent-002',
            hostname: 'SERVER-ABC',
            ip: '192.168.1.100',
            os: 'Windows Server 2022',
          },
          mitigationStatus: 'not mitigated',
        },
      ],
      totalCount: 2,
      pagination: {
        page: 1,
        pageSize: 50,
        totalPages: 1,
      },
    },
    sentinelone_agents: {
      agents: [
        {
          id: 'agent-001',
          hostname: 'DESKTOP-XYZ',
          status: 'online',
          agentVersion: '23.4.1',
          ip: '192.168.1.50',
          os: 'Windows 11 Pro',
        },
      ],
      totalCount: 1,
    },
    // Matches JiraIssueSchema: { key, summary, priority, status, assignee?, created?, labels? }
    jira_issues: {
      issues: [
        {
          key: 'SEC-001',
          summary: 'Critical CVE Found in Production',
          priority: 'High',
          status: 'Open',
          assignee: 'security-team',
          created: '2024-03-18T09:00:00Z',
          labels: ['security', 'critical', 'cve'],
        },
      ],
      total: 1,
    },
    // Matches TenableVulnerabilitySchema: { pluginId, name, severity, cvss?, description?, solution?, host?, protocol? }
    'tenable-io_vulns': {
      vulnerabilities: [
        {
          pluginId: 19506,
          name: 'Nginx Version Detection',
          severity: 2,
          cvss: 3.5,
          description: 'Nginx web server version detected',
          solution: 'N/A - informational only',
          host: '10.0.0.5',
          protocol: 'tcp',
        },
      ],
      total: 1,
    },
    'tenable-io_assets': {
      assets: [
        {
          id: 'tenable-asset-001',
          hostname: 'app-server-01',
          ip: '10.0.0.5',
          operatingSystem: 'Linux',
          lastSeen: '2024-03-20T10:00:00Z',
          source: 'tenable-io',
        },
      ],
      count: 1,
    },
  }

  return responses[key] ?? { data: [], total: 0, message: 'No mock data for this endpoint' }
}

function startMockServer(port = DEFAULT_MOCK_CONFIG.port) {
  return new Promise((resolve) => {
    const server = app.listen(port, () => {
      console.log(`Mock server running on http://localhost:${port}`)
      resolve(server)
    })
  })
}

module.exports = {
  app,
  configureMockServer,
  getMockResponse,
  getMockConfig,
  startMockServer,
  DEFAULT_MOCK_CONFIG,
}
