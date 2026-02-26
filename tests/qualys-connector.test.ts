// ============================================
// QUALYS CONNECTOR TEST
// ============================================
// Run: npx ts-node tests/qualys-connector.test.ts
// ============================================

import {
  QualysConnector,
  QualysScanStatus,
  QualysScanType,
  QUALYS_BASE_URLS,
  QUALYS_SEVERITY_MAP,
  parseHostDetections,
  parseVulnerabilityKB,
  enrichVulnerabilitiesWithKB,
} from '../src/connectors/qualys'

// ============================================
// Test Configuration
// ============================================

const TEST_CONFIG = {
  baseUrl: process.env.COMPLYMENT_QUALYS_BASE_URL || QUALYS_BASE_URLS.US1,
  username: process.env.COMPLYMENT_QUALYS_USERNAME || 'test_user',
  password: process.env.COMPLYMENT_QUALYS_PASSWORD || 'test_pass',
  timeout: 30000,
  dryRun: true, // Set to false for real API calls
}

// ============================================
// Test Utilities
// ============================================

let passCount = 0
let failCount = 0

function test(name: string, fn: () => void | Promise<void>) {
  return async () => {
    try {
      await fn()
      console.log(`✅ PASS: ${name}`)
      passCount++
    } catch (error: any) {
      console.log(`❌ FAIL: ${name}`)
      console.log(`   Error: ${error.message}`)
      failCount++
    }
  }
}

function assert(condition: boolean, message: string) {
  if (!condition) throw new Error(message)
}

function assertEqual<T>(actual: T, expected: T, message: string) {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${expected}, got ${actual}`)
  }
}

// ============================================
// Unit Tests - Types & Constants
// ============================================

const testConstants = test('Constants are defined correctly', () => {
  assert(QUALYS_BASE_URLS.US1 === 'https://qualysapi.qualys.com', 'US1 URL should match')
  assert(QUALYS_BASE_URLS.EU1 === 'https://qualysapi.qualys.eu', 'EU1 URL should match')
  assert(QUALYS_BASE_URLS.IN1 === 'https://qualysapi.qg1.apps.qualys.in', 'IN1 URL should match')
  assert(QUALYS_SEVERITY_MAP[5] === 'Critical', 'Severity 5 should be Critical')
  assert(QUALYS_SEVERITY_MAP[1] === 'Informational', 'Severity 1 should be Informational')
})

const testEnums = test('Enums are defined correctly', () => {
  assert(QualysScanStatus.RUNNING === 'Running', 'RUNNING status should match')
  assert(QualysScanStatus.FINISHED === 'Finished', 'FINISHED status should match')
  assert(QualysScanType.VM === 'VM', 'VM type should match')
  assert(QualysScanType.WAS === 'WAS', 'WAS type should match')
})

// ============================================
// Unit Tests - Parser Functions
// ============================================

const testParseHostDetectionsLegacy = test('parseHostDetections handles legacy XML format', () => {
  const mockResponse = {
    host_list_vm_detection_output: {
      response: {
        host_list: {
          host: [
            {
              id: '12345',
              ip: '192.168.1.100',
              dns: 'server1.example.com',
              os: 'Windows Server 2019',
              detection_list: {
                detection: [
                  {
                    qid: '90001',
                    severity: '5',
                    status: 'Active',
                    first_found_datetime: '2024-01-01T00:00:00Z',
                    results: 'Vulnerability detected on port 443',
                  },
                  {
                    qid: '90002',
                    severity: '3',
                    status: 'Active',
                    results: 'Medium severity issue',
                  },
                ],
              },
            },
          ],
        },
      },
    },
  }

  const result = parseHostDetections(mockResponse, 'Test Scan')

  assert(result.scanTitle === 'Test Scan', 'Scan title should match')
  assert(result.hostsScanned === 1, 'Should have 1 host')
  assert(result.totalVulnerabilities === 2, 'Should have 2 vulnerabilities')
  assert(result.criticalCount === 1, 'Should have 1 critical')
  assert(result.mediumCount === 1, 'Should have 1 medium')
  assert(result.vulnerabilities[0].qid === 90001, 'First vuln QID should be 90001')
  assert(result.vulnerabilities[0].severity === 5, 'First vuln severity should be 5')
})

const testParseHostDetectionsQPS = test('parseHostDetections handles QPS JSON format', () => {
  const mockResponse = {
    ServiceResponse: {
      data: [
        {
          HostAsset: {
            id: '67890',
            address: '10.0.0.50',
            dnsHostName: 'webserver.example.com',
            os: 'Ubuntu 22.04',
            vuln: {
              list: [
                {
                  HostAssetVuln: {
                    qid: '80001',
                    severity: '4',
                    firstFound: '2024-02-15T10:00:00Z',
                    port: '22',
                    protocol: 'TCP',
                  },
                },
              ],
            },
          },
        },
      ],
    },
  }

  const result = parseHostDetections(mockResponse, 'QPS Test')

  assert(result.scanTitle === 'QPS Test', 'Scan title should match')
  assert(result.hostsScanned === 1, 'Should have 1 host')
  assert(result.totalVulnerabilities === 1, 'Should have 1 vulnerability')
  assert(result.highCount === 1, 'Should have 1 high severity')
  assert(result.vulnerabilities[0].port === 22, 'Port should be 22')
  assert(result.vulnerabilities[0].protocol === 'TCP', 'Protocol should be TCP')
})

const testParseEmptyResponse = test('parseHostDetections handles empty response', () => {
  const result = parseHostDetections({}, 'Empty Scan')

  assert(result.totalVulnerabilities === 0, 'Should have 0 vulnerabilities')
  assert(result.hostsScanned === 0, 'Should have 0 hosts')
  assert(result.vulnerabilities.length === 0, 'Vulnerabilities array should be empty')
})

const testParseVulnerabilityKB = test('parseVulnerabilityKB parses KB data correctly', () => {
  const mockResponse = {
    knowledge_base_vuln_list_output: {
      response: {
        vuln_list: {
          vuln: [
            {
              qid: '90001',
              title: 'Critical SSL Vulnerability',
              severity_level: '5',
              category: 'SSL',
              patchable: 'true',
              diagnosis: 'SSL certificate is expired',
              solution: 'Renew SSL certificate',
              cvss: { base: '9.8' },
              cvss_v3: { base: '10.0' },
              cve_list: {
                cve: [{ id: 'CVE-2024-1234' }, { id: 'CVE-2024-5678' }],
              },
              pci_flag: 'true',
            },
          ],
        },
      },
    },
  }

  const kbMap = parseVulnerabilityKB(mockResponse)

  assert(kbMap.size === 1, 'Should have 1 KB entry')

  const entry = kbMap.get(90001)
  assert(entry !== undefined, 'Entry should exist')
  assert(entry!.title === 'Critical SSL Vulnerability', 'Title should match')
  assert(entry!.severityLevel === 5, 'Severity should be 5')
  assert(entry!.patchable === true, 'Should be patchable')
  assert(entry!.cvssBase === 9.8, 'CVSS base should be 9.8')
  assert(entry!.cvss3Base === 10.0, 'CVSS3 base should be 10.0')
  assert(entry!.cveList.length === 2, 'Should have 2 CVEs')
  assert(entry!.cveList[0] === 'CVE-2024-1234', 'First CVE should match')
  assert(entry!.pciFlag === true, 'PCI flag should be true')
})

const testEnrichVulnerabilities = test('enrichVulnerabilitiesWithKB enriches data correctly', () => {
  const vulnerabilities = [
    {
      qid: 90001,
      title: 'QID-90001',
      severity: 5 as const,
      ip: '192.168.1.1',
    },
  ]

  const kbMap = new Map([
    [90001, {
      qid: 90001,
      title: 'Critical SSL Vulnerability',
      severityLevel: 5,
      patchable: true,
      solution: 'Update SSL',
      cveList: ['CVE-2024-1234'],
      cvssBase: 9.8,
      cvss3Base: 10.0,
      pciFlag: true,
      pciReasons: [],
      vendorReferenceList: [],
      bugtraqList: [],
    }],
  ])

  const enriched = enrichVulnerabilitiesWithKB(vulnerabilities, kbMap)

  assert(enriched[0].title === 'Critical SSL Vulnerability', 'Title should be enriched')
  assert(enriched[0].solution === 'Update SSL', 'Solution should be enriched')
  assert(enriched[0].cvssBase === 9.8, 'CVSS should be enriched')
  assert(enriched[0].cveList?.length === 1, 'CVE list should be enriched')
  assert(enriched[0].patchable === true, 'Patchable should be enriched')
})

// ============================================
// Integration Tests - Connector
// ============================================

const testConnectorInitialization = test('QualysConnector initializes correctly', () => {
  const connector = new QualysConnector(TEST_CONFIG)
  assert(connector !== undefined, 'Connector should be created')
})

const testHealthCheck = test('QualysConnector healthCheck works', async () => {
  const connector = new QualysConnector({ ...TEST_CONFIG, dryRun: true })
  const result = await connector.healthCheck()
  assert(result !== undefined, 'Health check should return result')
  assert(result.connector === 'qualys', 'Connector name should be qualys')
})

const testGetAssets = test('QualysConnector getAssets returns response structure', async () => {
  const connector = new QualysConnector({ ...TEST_CONFIG, dryRun: true })
  const result = await connector.getAssets()
  // In dry run mode, result may have success=true with undefined data or fail auth
  // We just verify the response structure is correct
  assert(result !== undefined, 'Should return a response')
  assert('success' in result, 'Response should have success field')
  assert('timestamp' in result, 'Response should have timestamp field')
})

const testGetVulnerabilities = test('QualysConnector getVulnerabilities returns response structure', async () => {
  const connector = new QualysConnector({ ...TEST_CONFIG, dryRun: true })
  try {
    const result = await connector.getVulnerabilities()
    // In dry run mode without real creds, we just verify response structure
    assert(result !== undefined, 'Should return a response')
    assert('success' in result, 'Response should have success field')
  } catch (error: any) {
    // Authentication error is expected without real credentials
    assert(error.message.includes('Authentication') || error.message.includes('auth'),
      'Error should be auth-related without real credentials')
  }
})

// ============================================
// Run All Tests
// ============================================

async function runTests() {
  console.log('\n========================================')
  console.log('QUALYS CONNECTOR TEST SUITE')
  console.log('========================================\n')

  console.log('--- Constants & Enums ---')
  await testConstants()
  await testEnums()

  console.log('\n--- Parser Functions ---')
  await testParseHostDetectionsLegacy()
  await testParseHostDetectionsQPS()
  await testParseEmptyResponse()
  await testParseVulnerabilityKB()
  await testEnrichVulnerabilities()

  console.log('\n--- Connector Integration ---')
  await testConnectorInitialization()
  await testHealthCheck()
  await testGetAssets()
  await testGetVulnerabilities()

  console.log('\n========================================')
  console.log(`RESULTS: ${passCount} passed, ${failCount} failed`)
  console.log('========================================\n')

  if (failCount > 0) {
    process.exit(1)
  }
}

runTests().catch((error) => {
  console.error('Test suite failed:', error)
  process.exit(1)
})
