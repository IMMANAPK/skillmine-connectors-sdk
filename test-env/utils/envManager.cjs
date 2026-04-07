const MOCK_BASE_URL = 'http://localhost:3100'

const MockEnvMode = {
  MOCK: 'mock',
  REAL: 'real',
  HYBRID: 'hybrid',
}

const envConfigs = new Map()

function configureConnector(name, config) {
  envConfigs.set(name, config)
}

function getConnectorConfig(name) {
  return envConfigs.get(name)
}

function setMockMode() {
  process.env.COMPLYMENT_ENV_MODE = MockEnvMode.MOCK
  process.env.COMPLYMENT_QUALYS_BASE_URL = `${MOCK_BASE_URL}/qualys`
  process.env.COMPLYMENT_SENTINELONE_BASE_URL = `${MOCK_BASE_URL}/sentinelone`
  process.env.COMPLYMENT_JIRA_BASE_URL = `${MOCK_BASE_URL}/jira`
  process.env.COMPLYMENT_TENABLE_IO_BASE_URL = `${MOCK_BASE_URL}/tenable-io`
  process.env.COMPLYMENT_TENABLE_SC_BASE_URL = `${MOCK_BASE_URL}/tenable-sc`
  console.log('Environment set to MOCK mode')
}

function setRealMode() {
  process.env.COMPLYMENT_ENV_MODE = MockEnvMode.REAL
  console.log('Environment set to REAL mode')
}

function getCurrentMode() {
  return process.env.COMPLYMENT_ENV_MODE ?? MockEnvMode.MOCK
}

function isMockMode() {
  return getCurrentMode() === MockEnvMode.MOCK
}

function isRealMode() {
  return getCurrentMode() === MockEnvMode.REAL
}

function getBaseUrl(connectorName) {
  if (isMockMode()) {
    return `${MOCK_BASE_URL}/${connectorName.toLowerCase()}`
  }
  const envVar = `COMPLYMENT_${connectorName.toUpperCase()}_BASE_URL`
  return process.env[envVar] ?? ''
}

function switchEnv(mode) {
  if (mode === 'mock') {
    setMockMode()
  } else {
    setRealMode()
  }
}

module.exports = {
  MockEnvMode,
  configureConnector,
  getConnectorConfig,
  setMockMode,
  setRealMode,
  getCurrentMode,
  isMockMode,
  isRealMode,
  getBaseUrl,
  switchEnv,
}