// ============================================
// HTTP UTILITY - Skillmine Connectors SDK
// ============================================

import axios, { AxiosInstance, AxiosRequestConfig } from 'axios'

// ============================================
// Create HTTP Client
// ============================================

export function createHttpClient(
  baseURL: string,
  timeout = 30000,
  extraHeaders?: Record<string, string>,
): AxiosInstance {
  return axios.create({
    baseURL,
    timeout,
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      ...extraHeaders,
    },
  })
}

// ============================================
// Build Query String
// ============================================

export function buildQueryString(params: Record<string, unknown>): string {
  const filtered = Object.entries(params)
    .filter(([_, v]) => v !== undefined && v !== null)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
  return filtered.length ? `?${filtered.join('&')}` : ''
}

// ============================================
// Parse Retry After Header
// ============================================

export function parseRetryAfter(header?: string): number {
  if (!header) return 5000
  const seconds = parseInt(header, 10)
  return isNaN(seconds) ? 5000 : seconds * 1000
}

// ============================================
// Is Retryable Status Code
// ============================================

export function isRetryable(statusCode: number): boolean {
  return [408, 429, 500, 502, 503, 504].includes(statusCode)
}

// ============================================
// Merge Axios Config
// ============================================

export function mergeConfig(
  base: AxiosRequestConfig,
  override: AxiosRequestConfig,
): AxiosRequestConfig {
  return {
    ...base,
    ...override,
    headers: {
      ...base.headers,
      ...override.headers,
    },
  }
}