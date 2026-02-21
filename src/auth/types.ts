// ============================================
// AUTH TYPES - Skillmine Connectors SDK
// ============================================

export interface TokenResponse {
  accessToken: string
  tokenType: string
  expiresIn: number
  refreshToken?: string
  scope?: string
}

export interface OAuth2TokenRequest {
  grantType: 'client_credentials' | 'authorization_code' | 'refresh_token'
  clientId: string
  clientSecret: string
  scope?: string
  code?: string
  refreshToken?: string
  redirectUri?: string
}

export interface AuthResult {
  success: boolean
  token?: string
  expiresIn?: number
  error?: string
}