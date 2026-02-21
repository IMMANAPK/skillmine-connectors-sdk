// ============================================
// CUSTOM ERRORS - Skillmine Connectors SDK
// ============================================

export class SDKError extends Error {
  constructor(
    message: string,
    public readonly code: string,
    public readonly connector?: string,
    public readonly statusCode?: number,
  ) {
    super(message)
    this.name = 'SDKError'
    Object.setPrototypeOf(this, new.target.prototype)
  }
}

// ============================================
// Auth Errors
// ============================================

export class AuthenticationError extends SDKError {
  constructor(connector: string, message = 'Authentication failed') {
    super(message, 'AUTH_ERROR', connector, 401)
    this.name = 'AuthenticationError'
  }
}

export class TokenExpiredError extends SDKError {
  constructor(connector: string) {
    super('Token has expired', 'TOKEN_EXPIRED', connector, 401)
    this.name = 'TokenExpiredError'
  }
}

export class InvalidCredentialsError extends SDKError {
  constructor(connector: string) {
    super('Invalid credentials provided', 'INVALID_CREDENTIALS', connector, 403)
    this.name = 'InvalidCredentialsError'
  }
}

// ============================================
// Connection Errors
// ============================================

export class ConnectionError extends SDKError {
  constructor(connector: string, message = 'Connection failed') {
    super(message, 'CONNECTION_ERROR', connector, 503)
    this.name = 'ConnectionError'
  }
}

export class TimeoutError extends SDKError {
  constructor(connector: string, timeoutMs: number) {
    super(`Request timed out after ${timeoutMs}ms`, 'TIMEOUT', connector, 408)
    this.name = 'TimeoutError'
  }
}

// ============================================
// Rate Limit Errors
// ============================================

export class RateLimitError extends SDKError {
  constructor(
    connector: string,
    public readonly retryAfter?: number,
  ) {
    super('Rate limit exceeded', 'RATE_LIMIT_EXCEEDED', connector, 429)
    this.name = 'RateLimitError'
  }
}

// ============================================
// Validation Errors
// ============================================

export class ValidationError extends SDKError {
  constructor(
    message: string,
    public readonly field?: string,
  ) {
    super(message, 'VALIDATION_ERROR', undefined, 400)
    this.name = 'ValidationError'
  }
}

export class ConfigurationError extends SDKError {
  constructor(message: string, connector?: string) {
    super(message, 'CONFIGURATION_ERROR', connector, 400)
    this.name = 'ConfigurationError'
  }
}

// ============================================
// API Errors
// ============================================

export class APIError extends SDKError {
  constructor(
    connector: string,
    statusCode: number,
    message: string,
    public readonly response?: unknown,
  ) {
    super(message, 'API_ERROR', connector, statusCode)
    this.name = 'APIError'
  }
}

export class NotFoundError extends SDKError {
  constructor(connector: string, resource: string) {
    super(`${resource} not found`, 'NOT_FOUND', connector, 404)
    this.name = 'NotFoundError'
  }
}

// ============================================
// Circuit Breaker Errors
// ============================================

export class CircuitBreakerOpenError extends SDKError {
  constructor(connector: string) {
    super(
      `Circuit breaker is open for ${connector}. Too many failures.`,
      'CIRCUIT_BREAKER_OPEN',
      connector,
      503,
    )
    this.name = 'CircuitBreakerOpenError'
  }
}

// ============================================
// Plugin Errors
// ============================================

export class PluginNotFoundError extends SDKError {
  constructor(connectorName: string) {
    super(`Connector plugin '${connectorName}' not found`, 'PLUGIN_NOT_FOUND')
    this.name = 'PluginNotFoundError'
  }
}

export class DuplicatePluginError extends SDKError {
  constructor(connectorName: string) {
    super(`Connector plugin '${connectorName}' already registered`, 'DUPLICATE_PLUGIN')
    this.name = 'DuplicatePluginError'
  }
}