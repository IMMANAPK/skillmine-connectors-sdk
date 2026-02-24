// ============================================
// ZOHO TYPES - Complyment Connectors SDK
// ============================================

// ============================================
// Config
// ============================================

export interface ZohoConfig {
  baseUrl: string
  clientId: string
  clientSecret: string
  refreshToken: string
  accountsUrl?: string   // default: https://accounts.zoho.com
  timeout?: number
  retries?: number
  cache?: { enabled: boolean; ttl: number }
  dryRun?: boolean
}

// ============================================
// Contact
// ============================================

export interface ZohoContact {
  id: string
  firstName?: string
  lastName: string
  email?: string
  phone?: string
  mobile?: string
  accountName?: string
  title?: string
  department?: string
  leadSource?: string
  createdAt: string
  updatedAt: string
  ownerId?: string
}

export interface ZohoContactListResponse {
  data: ZohoContact[]
  info: {
    count: number
    moreRecords: boolean
    page: number
    perPage: number
  }
}

// ============================================
// Lead
// ============================================

export type ZohoLeadStatus =
  | 'Not Contacted'
  | 'Attempted to Contact'
  | 'Contact in Future'
  | 'Contacted'
  | 'Junk Lead'
  | 'Lost Lead'
  | 'Not Qualified'
  | 'Pre-Qualified'

export interface ZohoLead {
  id: string
  firstName?: string
  lastName: string
  email?: string
  phone?: string
  company: string
  title?: string
  status: ZohoLeadStatus
  leadSource?: string
  industry?: string
  annualRevenue?: number
  noOfEmployees?: number
  rating?: string
  website?: string
  createdAt: string
  updatedAt: string
}

// ============================================
// Account
// ============================================

export interface ZohoAccount {
  id: string
  accountName: string
  website?: string
  phone?: string
  industry?: string
  annualRevenue?: number
  noOfEmployees?: number
  billingCity?: string
  billingCountry?: string
  description?: string
  createdAt: string
  updatedAt: string
}

// ============================================
// Deal
// ============================================

export type ZohoDealStage =
  | 'Qualification'
  | 'Needs Analysis'
  | 'Value Proposition'
  | 'Id. Decision Makers'
  | 'Perception Analysis'
  | 'Proposal/Price Quote'
  | 'Negotiation/Review'
  | 'Closed Won'
  | 'Closed Lost'

export interface ZohoDeal {
  id: string
  dealName: string
  accountName?: string
  stage: ZohoDealStage
  amount?: number
  closingDate?: string
  probability?: number
  leadSource?: string
  contactName?: string
  description?: string
  createdAt: string
  updatedAt: string
}

// ============================================
// Activity / Task
// ============================================

export type ZohoTaskStatus =
  | 'Not Started'
  | 'Deferred'
  | 'In Progress'
  | 'Completed'
  | 'Waiting for input'

export interface ZohoTask {
  id: string
  subject: string
  status: ZohoTaskStatus
  dueDate?: string
  priority?: 'High' | 'Medium' | 'Low'
  description?: string
  contactId?: string
  accountId?: string
  dealId?: string
  createdAt: string
  updatedAt: string
}

// ============================================
// Filters
// ============================================

export interface ZohoContactFilter {
  page?: number
  perPage?: number
  searchBy?: string
  sortBy?: string
  sortOrder?: 'asc' | 'desc'
}

export interface ZohoLeadFilter {
  page?: number
  perPage?: number
  status?: ZohoLeadStatus[]
  searchBy?: string
  sortBy?: string
  sortOrder?: 'asc' | 'desc'
}

export interface ZohoDealFilter {
  page?: number
  perPage?: number
  stage?: ZohoDealStage[]
  searchBy?: string
  sortBy?: string
  sortOrder?: 'asc' | 'desc'
}

// ============================================
// Search
// ============================================

export interface ZohoSearchResponse<T> {
  data: T[]
  info: {
    count: number
    moreRecords: boolean
  }
}