const ERROR_SCENARIOS = {
  rate_limit: {
    type: 'rate_limit',
    statusCode: 429,
    message: 'Rate limit exceeded. Please retry after 60 seconds.',
    headers: {
      'Retry-After': '60',
      'X-RateLimit-Limit': '100',
      'X-RateLimit-Remaining': '0',
    },
  },
  timeout: {
    type: 'timeout',
    statusCode: 408,
    message: 'Request timeout',
    delay: 35000,
  },
  auth_failure: {
    type: 'auth_failure',
    statusCode: 401,
    message: 'Authentication failed. Invalid or expired token.',
    headers: {
      'WWW-Authenticate': 'Bearer realm="api"',
    },
  },
  server_error: {
    type: 'server_error',
    statusCode: 500,
    message: 'Internal server error. Please try again later.',
  },
  connection_refused: {
    type: 'connection_refused',
    statusCode: 503,
    message: 'Service temporarily unavailable',
  },
}

const settings = {
  enabled: false,
  probability: 0,
}

function configureErrorInjection(config) {
  Object.assign(settings, config)
}

function getErrorInjectionSettings() {
  return { ...settings }
}

function shouldInjectError() {
  if (!settings.enabled) return false
  if (settings.probability <= 0) return false
  return Math.random() < settings.probability
}

function injectError(type) {
  if (!shouldInjectError()) return null
  const errorType = type ?? settings.errorType
  if (!errorType) return null
  const scenario = ERROR_SCENARIOS[errorType]
  if (!scenario) return null
  return { ...scenario }
}

function enableRandomErrors(probability = 0.1) {
  configureErrorInjection({ enabled: true, probability })
}

function disableErrors() {
  configureErrorInjection({ enabled: false, probability: 0 })
}

function enableSpecificError(type, probability = 1) {
  configureErrorInjection({ enabled: true, errorType: type, probability })
}

module.exports = {
  ERROR_SCENARIOS,
  configureErrorInjection,
  getErrorInjectionSettings,
  shouldInjectError,
  injectError,
  enableRandomErrors,
  disableErrors,
  enableSpecificError,
}