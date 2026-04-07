const MOCK_BASE_URL = 'http://localhost:3100'

const MockEnvMode = {
  MOCK: 'mock',
  REAL: 'real',
  HYBRID: 'hybrid',
}

const DEFAULT_MOCK_CONFIG = {
  mode: MockEnvMode.MOCK,
  port: 3100,
  host: 'localhost',
  errorInjection: {
    enabled: false,
    rateLimitProbability: 0.1,
    timeoutProbability: 0.05,
    authFailureProbability: 0.05,
    serverErrorProbability: 0.02,
    throttleProbability: 0.1,
  },
  responseDelay: 50,
  enableLogging: true,
}

function getEnvVar(name) {
  return process.env[`COMPLYMENT_${name}`]
}

function setEnvVar(name, value) {
  process.env[`COMPLYMENT_${name}`] = value
}

module.exports = {
  MockEnvMode,
  DEFAULT_MOCK_CONFIG,
  MOCK_BASE_URL,
  getEnvVar,
  setEnvVar,
}