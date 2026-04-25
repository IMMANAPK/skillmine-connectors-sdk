#!/usr/bin/env node

const { performance } = require('perf_hooks')
const { getMockResponse } = require('../../test-env/server/mockServer.cjs')

async function runBenchmarks() {
  console.log('\n=== Performance Benchmarks ===\n')

  console.log('Benchmark: Qualys getVulns (mock response)')
  const start1 = performance.now()
  for (let i = 0; i < 10; i++) {
    getMockResponse('qualys', 'vulns', {})
  }
  const time1 = (performance.now() - start1) / 10
  console.log(`  Average latency: ${time1.toFixed(2)}ms`)

  console.log('\nBenchmark: SentinelOne getThreats (mock response)')
  const start2 = performance.now()
  for (let i = 0; i < 10; i++) {
    getMockResponse('sentinelone', 'threats', {})
  }
  const time2 = (performance.now() - start2) / 10
  console.log(`  Average latency: ${time2.toFixed(2)}ms`)

  console.log('\n✓ Benchmarks complete')
}

runBenchmarks().catch(console.error)
