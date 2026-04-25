#!/usr/bin/env node

const { setMockMode } = require('../test-env/utils/envManager.cjs')
const { getMockResponse, startMockServer } = require('../test-env/server/mockServer.cjs')

async function quickDemo() {
  console.log(`
╔════════════════════════════════════════════════════════════╗
║     Complyment Connectors SDK - Quick Demo                ║
╚════════════════════════════════════════════════════════════╝
`)

  console.log('Starting mock server...')
  const server = await startMockServer(3100)
  setMockMode()

  console.log('\n✓ Mock server running at http://localhost:3100')
  console.log('✓ Environment set to MOCK mode')
  console.log('\nTesting endpoints...\n')

  const endpoints = [
    { name: 'Health Check', url: 'http://localhost:3100/api/health', fallback: () => ({ status: 'ok' }) },
    { name: 'Qualys Vulnerabilities', url: 'http://localhost:3100/api/qualys/vulns', fallback: () => getMockResponse('qualys', 'vulns', {}) },
    { name: 'SentinelOne Threats', url: 'http://localhost:3100/api/sentinelone/threats', fallback: () => getMockResponse('sentinelone', 'threats', {}) },
    { name: 'Jira Issues', url: 'http://localhost:3100/api/jira/issues', fallback: () => getMockResponse('jira', 'issues', {}) },
  ]

  try {
    for (const endpoint of endpoints) {
      const start = Date.now()

      try {
        const res = await fetch(endpoint.url)
        await res.json()
        const latency = Date.now() - start

        const status = res.ok ? '✓' : '✗'
        console.log(`${status} ${endpoint.name} (${latency}ms) - Status: ${res.status}`)
      } catch (error) {
        endpoint.fallback()
        const latency = Date.now() - start
        console.log(`✓ ${endpoint.name} (${latency}ms) - Mock fallback`)
      }
    }

    console.log(`
╔════════════════════════════════════════════════════════════╗
║                    Demo Complete!                          ║
╠════════════════════════════════════════════════════════════╣
║  Next steps:                                                ║
║    npm test          # Run unit checks                     ║
║    npm run build     # Build the SDK                       ║
║    npm run eval      # Interactive evaluation              ║
╚════════════════════════════════════════════════════════════╝
`)
  } finally {
    server.close()
  }
}

quickDemo().catch(console.error)
