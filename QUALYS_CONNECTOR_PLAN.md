# Qualys Connector Enhancement Plan

## Overview

Enhance the SDK's Qualys connector based on the tested production code from `qualys-integration-srv`.

---

## Current State Analysis

### SDK Qualys Connector (Basic)
```
src/connectors/qualys/
├── QualysConnector.ts    # Basic connector with placeholder methods
├── types.ts              # Simple type definitions
└── index.ts              # Exports
```

### Production Code (Tested & Complete)
```
qualys-integration-srv/
├── constants/
│   └── qualys.constants.ts       # API paths, defaults, severity mapping
├── model/
│   ├── collections/
│   │   └── QualysScan.ts         # MongoDB schema (skip - SDK is stateless)
│   ├── entity/
│   │   ├── QualysScanAndUploadRequest.ts
│   │   ├── QualysScanDetail.ts
│   │   ├── QualysScanList.ts
│   │   ├── QualysScanRequest.ts
│   │   ├── QualysVulnerability.ts
│   │   └── UploadExistingScan.ts
│   └── enums/
│       ├── QualysScanStatus.ts
│       ├── QualysScanType.ts
│       └── QualysSeverity.ts
└── service/
    ├── QualysApiService.ts           # Core API communication
    ├── QualysScanService.ts          # Scan operations (DB-dependent - adapt)
    ├── QualysReportParserService.ts  # Response parsing
    ├── QualysReportTransformer.ts    # Data transformation
    └── QualysOrchestrationService.ts # Workflow (skip - BE specific)
```

---

## Implementation Plan

### Phase 1: Types & Constants

**Task 1.1: Add Constants**
- [ ] Create `src/connectors/qualys/constants.ts`
- [ ] Add `QUALYS_BASE_URLS` (regional endpoints)
- [ ] Add `QUALYS_VM_API_PATHS` (VM API endpoints)
- [ ] Add `QUALYS_WAS_API_PATHS` (WAS API endpoints)
- [ ] Add `QUALYS_DEFAULTS` (timeouts, retries)
- [ ] Add `QUALYS_SEVERITY_MAP`

**Task 1.2: Add Enums**
- [ ] Add `QualysScanStatus` enum to types.ts
- [ ] Add `QualysScanType` enum to types.ts
- [ ] Add helper functions (`isQualysScanTerminal`, `isQualysScanActive`)

**Task 1.3: Enhance Types**
- [ ] Add `IQualysVulnerability` interface (full fields from production)
- [ ] Add `IQualysHostDetection` interface
- [ ] Add `IQualysParsedReport` interface
- [ ] Add `IQualysScanRequest` interface
- [ ] Add `IQualysScanResponse` interface
- [ ] Add WAS-specific types

---

### Phase 2: Core API Methods

**Task 2.1: Enhance QualysConnector**
Based on `QualysApiService.ts`:

**VM API Methods:**
- [ ] `launchVMScan(params)` - Launch vulnerability scan
- [ ] `getScanStatus(scanRef)` - Get scan status
- [ ] `fetchHostDetections(params)` - Fetch vulnerabilities (QPS + Legacy)
- [ ] `fetchVulnerabilityKB(qids)` - Fetch KB data
- [ ] `cancelScan(scanRef)` - Cancel running scan
- [ ] `listVMScans(filters)` - List all VM scans

**WAS API Methods:**
- [ ] `listWASScans(filters)` - List WAS scans
- [ ] `listWASFindings(filters)` - List WAS findings/vulnerabilities

**General Methods:**
- [ ] `parseXml(xml)` - XML to JSON parsing
- [ ] Update `makeRequest()` to handle XML responses

---

### Phase 3: Report Parser

**Task 3.1: Create QualysReportParser**
- [ ] Create `src/connectors/qualys/parser.ts`
- [ ] `parseHostDetections()` - Parse VM vulnerabilities (QPS JSON + Legacy XML)
- [ ] `parseVulnerabilityKB()` - Parse KB response
- [ ] `enrichVulnerabilitiesWithKB()` - Merge vuln + KB data
- [ ] `parseWASFindings()` - Parse WAS vulnerabilities
- [ ] Helper methods for CVE, vendor refs, bugtraq extraction

---

### Phase 4: High-Level Operations

**Task 4.1: Add Scan Operations**
Stateless versions (no DB):

- [ ] `triggerScan(params)` - Launch scan, return scan_ref
- [ ] `pollScanStatus(scanRef, options)` - Poll until complete
- [ ] `getScanResults(scanRef)` - Fetch + parse results
- [ ] `getEnrichedResults(scanRef)` - Results with KB enrichment

**Task 4.2: Add Sync Operations**
- [ ] `syncVMScans()` - Fetch all VM scans from Qualys
- [ ] `syncWASScans()` - Fetch all WAS scans from Qualys

---

### Phase 5: Normalization

**Task 5.1: Update Normalization**
- [ ] Map Qualys vulnerability → `NormalizedVulnerability`
- [ ] Include all fields (CVE, CVSS, KB data)
- [ ] Map WAS findings → normalized format

---

## File Structure (After Enhancement)

```
src/connectors/qualys/
├── index.ts                    # Exports
├── QualysConnector.ts          # Main connector class
├── types.ts                    # All types & interfaces
├── constants.ts                # API paths, defaults, mappings
├── parser.ts                   # Response parsing utilities
└── utils.ts                    # Helper functions (XML parse, etc.)
```

---

## API Method Mapping

| Production Method | SDK Method | Notes |
|-------------------|------------|-------|
| `QualysApiService.launchVMScan` | `connector.launchVMScan()` | Direct port |
| `QualysApiService.getScanStatus` | `connector.getScanStatus()` | Direct port |
| `QualysApiService.fetchHostDetections` | `connector.fetchHostDetections()` | QPS + Legacy support |
| `QualysApiService.fetchVulnerabilityKB` | `connector.fetchVulnerabilityKB()` | Direct port |
| `QualysApiService.cancelScan` | `connector.cancelScan()` | Direct port |
| `QualysApiService.listVMScans` | `connector.listVMScans()` | Direct port |
| `QualysApiService.listWASScans` | `connector.listWASScans()` | Direct port |
| `QualysApiService.listWASFindings` | `connector.listWASFindings()` | Direct port |
| `QualysReportParserService.parseHostDetections` | `parser.parseHostDetections()` | Move to parser.ts |
| `QualysReportParserService.parseVulnerabilityKB` | `parser.parseVulnerabilityKB()` | Move to parser.ts |
| `QualysReportParserService.parseWASFindings` | `parser.parseWASFindings()` | Move to parser.ts |
| `QualysScanService.triggerScan` | `connector.triggerScan()` | Stateless version |
| `QualysScanService.getScanResults` | `connector.getScanResults()` | Stateless version |

---

## Dependencies to Add

```json
{
  "dependencies": {
    "xml2js": "^0.6.x"  // For XML parsing
  },
  "devDependencies": {
    "@types/xml2js": "^0.4.x"
  }
}
```

---

## Key Differences from Production

| Aspect | Production | SDK |
|--------|------------|-----|
| State Management | MongoDB | Stateless (return data) |
| Credentials | From DB connector | Config object |
| Logging | `@skillmine-dev/code-utils` | SDK Logger |
| Error Handling | `ErrorEntity` | SDK `ConnectorError` |
| Context | `RequestContext` | Optional trace context |
| Upload | VulnerabilityReportV2 API | Not included (BE specific) |

---

## Estimated Tasks

| Phase | Tasks | Priority |
|-------|-------|----------|
| Phase 1 | Types & Constants | High |
| Phase 2 | Core API Methods | High |
| Phase 3 | Report Parser | High |
| Phase 4 | High-Level Operations | Medium |
| Phase 5 | Normalization | Medium |

---

## Next Steps

1. Review and approve this plan
2. Start with Phase 1 (Types & Constants)
3. Implement Phase 2 (Core API)
4. Add tests using mock Qualys responses
5. Integration test with real Qualys credentials

---

## Questions Before Starting

1. **XML Parsing:** Add `xml2js` dependency? Or use built-in?
2. **WAS Support:** Include WAS (Web Application Scanning) or VM only?
3. **KB Enrichment:** Always enrich with KB data, or make optional?
4. **Polling:** Include built-in polling for scan completion?
5. **Regional URLs:** Auto-detect or require explicit config?
