// ============================================
// JIRA TYPES - Complyment Connectors SDK
// ============================================

// ============================================
// Config
// ============================================

export interface JiraConfig {
  baseUrl: string
  email: string
  apiToken: string
  timeout?: number
  retries?: number
  cache?: { enabled: boolean; ttl: number }
  dryRun?: boolean
}

// ============================================
// Project
// ============================================

export interface JiraProject {
  id: string
  key: string
  name: string
  projectTypeKey: string
  style: string
  isPrivate: boolean
  lead?: {
    accountId: string
    displayName: string
  }
}

// ============================================
// Issue
// ============================================

export type JiraIssuePriority =
  | 'Highest'
  | 'High'
  | 'Medium'
  | 'Low'
  | 'Lowest'

export type JiraIssueStatus =
  | 'To Do'
  | 'In Progress'
  | 'Done'
  | 'Blocked'
  | 'In Review'

export type JiraIssueType =
  | 'Bug'
  | 'Task'
  | 'Story'
  | 'Epic'
  | 'Subtask'

export interface JiraUser {
  accountId: string
  displayName: string
  emailAddress?: string
  active: boolean
}

export interface JiraIssue {
  id: string
  key: string
  summary: string
  description?: string
  status: JiraIssueStatus
  priority: JiraIssuePriority
  issueType: JiraIssueType
  projectKey: string
  assignee?: JiraUser
  reporter?: JiraUser
  labels?: string[]
  createdAt: string
  updatedAt: string
  dueDate?: string
  resolvedAt?: string
  components?: string[]
  customFields?: Record<string, unknown>
}

export interface JiraIssueListResponse {
  issues: JiraIssue[]
  total: number
  startAt: number
  maxResults: number
}

// ============================================
// Create / Update Issue
// ============================================

export interface JiraCreateIssueRequest {
  projectKey: string
  summary: string
  description?: string
  issueType: JiraIssueType
  priority?: JiraIssuePriority
  assigneeAccountId?: string
  labels?: string[]
  dueDate?: string
  components?: string[]
  customFields?: Record<string, unknown>
}

export interface JiraUpdateIssueRequest {
  summary?: string
  description?: string
  priority?: JiraIssuePriority
  assigneeAccountId?: string
  labels?: string[]
  dueDate?: string
  status?: JiraIssueStatus
}

// ============================================
// Comment
// ============================================

export interface JiraComment {
  id: string
  body: string
  author: JiraUser
  createdAt: string
  updatedAt: string
}

// ============================================
// Transition
// ============================================

export interface JiraTransition {
  id: string
  name: string
  to: {
    id: string
    name: string
  }
}

// ============================================
// Sprint
// ============================================

export type JiraSprintState = 'active' | 'closed' | 'future'

export interface JiraSprint {
  id: number
  name: string
  state: JiraSprintState
  startDate?: string
  endDate?: string
  completeDate?: string
  goal?: string
}

// ============================================
// Filters
// ============================================

export interface JiraIssueFilter {
  projectKey?: string
  status?: JiraIssueStatus[]
  priority?: JiraIssuePriority[]
  issueType?: JiraIssueType[]
  assigneeAccountId?: string
  labels?: string[]
  createdAfter?: string
  createdBefore?: string
  jql?: string           // Custom JQL query
  startAt?: number
  maxResults?: number
}