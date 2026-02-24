// ============================================
// SEMANTIC SEARCH - Complyment Connectors SDK
// ============================================
// RAG-based semantic search on connector data
// Natural language queries on security data
// ============================================

export interface SemanticDocument {
  id: string
  content: string
  metadata: {
    connector: string
    type: 'vulnerability' | 'asset' | 'threat' | 'log' | 'policy'
    severity?: string
    source?: string
    timestamp?: Date
    [key: string]: unknown
  }
  embedding?: number[]
}

export interface SemanticSearchResult {
  document: SemanticDocument
  score: number
  highlights?: string[]
}

export interface SemanticSearchOptions {
  topK?: number
  minScore?: number
  connector?: string
  type?: SemanticDocument['metadata']['type']
  filters?: Record<string, unknown>
}

export interface EmbeddingProvider {
  embed: (text: string) => Promise<number[]>
  embedBatch: (texts: string[]) => Promise<number[][]>
}

// ============================================
// Simple TF-IDF based search (no API needed)
// ============================================

class TFIDFIndex {
  private documents: SemanticDocument[] = []
  private termFrequency: Map<string, Map<string, number>> = new Map()
  private documentFrequency: Map<string, number> = new Map()

  addDocument(doc: SemanticDocument): void {
    this.documents.push(doc)
    const terms = this.tokenize(doc.content)
    const termCount = new Map<string, number>()

    for (const term of terms) {
      termCount.set(term, (termCount.get(term) ?? 0) + 1)
    }

    this.termFrequency.set(doc.id, termCount)

    for (const term of termCount.keys()) {
      this.documentFrequency.set(
        term,
        (this.documentFrequency.get(term) ?? 0) + 1,
      )
    }
  }

  search(query: string, topK = 5): Array<{ doc: SemanticDocument; score: number }> {
    const queryTerms = this.tokenize(query)
    const scores: Array<{ doc: SemanticDocument; score: number }> = []

    for (const doc of this.documents) {
      let score = 0
      const tf = this.termFrequency.get(doc.id) ?? new Map()
      const docLength = Array.from(tf.values()).reduce((a, b) => a + b, 0)

      for (const term of queryTerms) {
        const termFreq = (tf.get(term) ?? 0) / (docLength || 1)
        const docFreq = this.documentFrequency.get(term) ?? 0
        const idf = docFreq > 0
          ? Math.log(this.documents.length / docFreq)
          : 0
        score += termFreq * idf
      }

      if (score > 0) scores.push({ doc, score })
    }

    return scores
      .sort((a, b) => b.score - a.score)
      .slice(0, topK)
  }

  private tokenize(text: string): string[] {
    return text
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter((t) => t.length > 2)
  }

  clear(): void {
    this.documents = []
    this.termFrequency.clear()
    this.documentFrequency.clear()
  }

  size(): number {
    return this.documents.length
  }
}

// ============================================
// Cosine Similarity (for vector search)
// ============================================

function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) return 0

  let dotProduct = 0
  let normA = 0
  let normB = 0

  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i]
    normA += a[i] * a[i]
    normB += b[i] * b[i]
  }

  const denominator = Math.sqrt(normA) * Math.sqrt(normB)
  return denominator === 0 ? 0 : dotProduct / denominator
}

// ============================================
// Semantic Search Engine
// ============================================

export class SemanticSearch {
  private documents: SemanticDocument[] = []
  private tfidfIndex: TFIDFIndex = new TFIDFIndex()
  private embeddingProvider?: EmbeddingProvider
  private readonly useVectorSearch: boolean

  constructor(options?: {
    embeddingProvider?: EmbeddingProvider
    useVectorSearch?: boolean
  }) {
    this.embeddingProvider = options?.embeddingProvider
    this.useVectorSearch = options?.useVectorSearch ?? false
  }

  // ============================================
  // Index Documents
  // ============================================

  async indexDocument(doc: SemanticDocument): Promise<void> {
    // Generate embedding if provider available
    if (this.useVectorSearch && this.embeddingProvider && !doc.embedding) {
      doc.embedding = await this.embeddingProvider.embed(doc.content)
    }

    this.documents.push(doc)
    this.tfidfIndex.addDocument(doc)
  }

  async indexBatch(docs: SemanticDocument[]): Promise<void> {
    if (this.useVectorSearch && this.embeddingProvider) {
      const texts = docs.map((d) => d.content)
      const embeddings = await this.embeddingProvider.embedBatch(texts)
      docs.forEach((doc, i) => { doc.embedding = embeddings[i] })
    }

    for (const doc of docs) {
      this.documents.push(doc)
      this.tfidfIndex.addDocument(doc)
    }
  }

  // ============================================
  // Search
  // ============================================

  async search(
    query: string,
    options?: SemanticSearchOptions,
  ): Promise<SemanticSearchResult[]> {
    const topK = options?.topK ?? 10
    const minScore = options?.minScore ?? 0

    let results: SemanticSearchResult[]

    if (this.useVectorSearch && this.embeddingProvider) {
      results = await this.vectorSearch(query, topK)
    } else {
      results = this.keywordSearch(query, topK)
    }

    // Apply filters
    if (options?.connector) {
      results = results.filter(
        (r) => r.document.metadata.connector === options.connector,
      )
    }

    if (options?.type) {
      results = results.filter(
        (r) => r.document.metadata.type === options.type,
      )
    }

    if (options?.filters) {
      for (const [key, value] of Object.entries(options.filters)) {
        results = results.filter(
          (r) => r.document.metadata[key] === value,
        )
      }
    }

    return results.filter((r) => r.score >= minScore)
  }

  // ============================================
  // Keyword Search (TF-IDF)
  // ============================================

  private keywordSearch(
    query: string,
    topK: number,
  ): SemanticSearchResult[] {
    const results = this.tfidfIndex.search(query, topK)
    return results.map(({ doc, score }) => ({
      document: doc,
      score,
      highlights: this.extractHighlights(doc.content, query),
    }))
  }

  // ============================================
  // Vector Search (Cosine Similarity)
  // ============================================

  private async vectorSearch(
    query: string,
    topK: number,
  ): Promise<SemanticSearchResult[]> {
    if (!this.embeddingProvider) return []

    const queryEmbedding = await this.embeddingProvider.embed(query)
    const docsWithEmbeddings = this.documents.filter((d) => d.embedding)

    const scored = docsWithEmbeddings.map((doc) => ({
      document: doc,
      score: cosineSimilarity(queryEmbedding, doc.embedding!),
    }))

    return scored
      .sort((a, b) => b.score - a.score)
      .slice(0, topK)
      .map((r) => ({
        ...r,
        highlights: this.extractHighlights(r.document.content, query),
      }))
  }

  // ============================================
  // Index Connector Data
  // ============================================

  indexVulnerabilities(
    vulnerabilities: Array<{
      id: string
      title: string
      severity: string
      cve?: string
      affectedAsset: string
      source: string
    }>,
  ): void {
    const docs: SemanticDocument[] = vulnerabilities.map((vuln) => ({
      id: vuln.id,
      content: `${vuln.title} ${vuln.cve ?? ''} ${vuln.severity} severity vulnerability affecting ${vuln.affectedAsset}`,
      metadata: {
        connector: vuln.source,
        type: 'vulnerability',
        severity: vuln.severity,
        source: vuln.source,
      },
    }))

    docs.forEach((doc) => {
      this.documents.push(doc)
      this.tfidfIndex.addDocument(doc)
    })
  }

  indexThreats(
    threats: Array<{
      id: string
      name: string
      severity: string
      affectedAsset: string
      source: string
    }>,
  ): void {
    const docs: SemanticDocument[] = threats.map((threat) => ({
      id: threat.id,
      content: `${threat.name} ${threat.severity} threat detected on ${threat.affectedAsset}`,
      metadata: {
        connector: threat.source,
        type: 'threat',
        severity: threat.severity,
        source: threat.source,
      },
    }))

    docs.forEach((doc) => {
      this.documents.push(doc)
      this.tfidfIndex.addDocument(doc)
    })
  }

  indexAssets(
    assets: Array<{
      id: string
      hostname: string
      ipAddress: string
      os?: string
      source: string
    }>,
  ): void {
    const docs: SemanticDocument[] = assets.map((asset) => ({
      id: asset.id,
      content: `${asset.hostname} ${asset.ipAddress} ${asset.os ?? ''} asset from ${asset.source}`,
      metadata: {
        connector: asset.source,
        type: 'asset',
        source: asset.source,
      },
    }))

    docs.forEach((doc) => {
      this.documents.push(doc)
      this.tfidfIndex.addDocument(doc)
    })
  }

  // ============================================
  // Natural Language Queries
  // ============================================

  async findCriticalThreats(): Promise<SemanticSearchResult[]> {
    return this.search('critical high severity active threat malware', {
      type: 'threat',
      topK: 20,
    })
  }

  async findVulnerableAssets(hostname: string): Promise<SemanticSearchResult[]> {
    return this.search(`vulnerability affecting ${hostname}`, {
      type: 'vulnerability',
      topK: 10,
    })
  }

  async findByKeyword(keyword: string): Promise<SemanticSearchResult[]> {
    return this.search(keyword, { topK: 15 })
  }

  // ============================================
  // Extract Highlights
  // ============================================

  private extractHighlights(content: string, query: string): string[] {
    const queryWords = query.toLowerCase().split(/\s+/)
    const sentences = content.split(/[.!?]/)

    return sentences
      .filter((sentence) =>
        queryWords.some((word) =>
          sentence.toLowerCase().includes(word),
        ),
      )
      .slice(0, 3)
      .map((s) => s.trim())
      .filter((s) => s.length > 0)
  }

  // ============================================
  // Stats
  // ============================================

  getStats() {
    const byConnector: Record<string, number> = {}
    const byType: Record<string, number> = {}

    for (const doc of this.documents) {
      const connector = doc.metadata.connector
      const type = doc.metadata.type
      byConnector[connector] = (byConnector[connector] ?? 0) + 1
      byType[type] = (byType[type] ?? 0) + 1
    }

    return {
      totalDocuments: this.documents.length,
      byConnector,
      byType,
      vectorSearchEnabled: this.useVectorSearch,
    }
  }

  clearIndex(): void {
    this.documents = []
    this.tfidfIndex.clear()
  }
}

// ============================================
// Global Semantic Search Instance
// ============================================

export const semanticSearch = new SemanticSearch({
  useVectorSearch: false, // TF-IDF by default, no API needed
})