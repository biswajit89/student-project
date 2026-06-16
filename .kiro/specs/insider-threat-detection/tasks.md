# Implementation Plan: Insider Threat Detection System

## Overview

This plan implements the Insider Threat Detection System as a pipeline architecture with 8 core components: Data Collection Layer, Data Processing Pipeline, Feature Engineering Module, ML Anomaly Detection Engine, Risk Scoring Engine, Alert System, API Layer, and Dashboard. Tasks are ordered to establish foundational infrastructure first, then build components bottom-up from data ingestion through to the frontend dashboard.

## Tasks

- [ ] 1. Set up project structure, database schema, and core data models
  - [ ] 1.1 Initialize project structure with Docker Compose and dependency configuration
    - Create project directory layout: `src/`, `src/models/`, `src/services/`, `src/api/`, `src/ml/`, `src/workers/`, `tests/`, `frontend/`
    - Create `pyproject.toml` with dependencies: fastapi, uvicorn, sqlalchemy, asyncpg, pydantic, scikit-learn, pandas, numpy, celery, redis, python-jose, passlib, hypothesis, pytest, pytest-asyncio, factory_boy, testcontainers, httpx
    - Create `docker-compose.yml` with services: api-server, ingestion-worker, ml-engine, scheduler, worker, postgres, redis, nginx, dashboard
    - Create `Dockerfile` for Python backend and `frontend/Dockerfile` for React app
    - _Requirements: 10.1_

  - [ ] 1.2 Create database schema and SQLAlchemy models
    - Implement SQLAlchemy models for: Users, ActivityLogs, BehavioralBaselines, FeatureVectors, AnomalyDetections, RiskScores, RiskScoreHistory, Alerts, ModelVersions
    - Create Alembic migration for the complete schema including all indexes (composite indexes on activity_logs, risk_scores, alerts, feature_vectors, users)
    - Configure AES-256 encryption at rest via PostgreSQL TDE settings
    - Implement monthly partitioning for activity_logs table
    - _Requirements: 1.1, 1.4, 4.4_

  - [ ] 1.3 Create Pydantic data models and enums
    - Implement enums: SourceType, SeverityLevel, AlertStatus, WindowType, BaselineType
    - Implement Pydantic models: ActivityLogInput, AnomalyScores, RiskScoreResult, AnomalyExplanation, ContributingFactor
    - Implement request/response schemas for all API endpoints
    - Add field validators with constraints (score ranges, string lengths, etc.)
    - _Requirements: 1.1, 1.2, 4.1, 10.6_

  - [ ]* 1.4 Write property test for activity log validation (Property 1)
    - **Property 1: Activity log validation accepts valid records and rejects invalid records**
    - Generate random activity log records with valid/invalid combinations of mandatory fields
    - Verify acceptance iff all mandatory fields present with correct types and valid source_type
    - Verify rejection returns error identifying failing field(s)
    - **Validates: Requirements 1.1, 1.2, 1.3**

- [ ] 2. Implement Data Collection Layer
  - [ ] 2.1 Implement ingestion API endpoints and schema validation
    - Create `src/services/data_collection.py` with `DataCollectionService` class
    - Implement `ingest_log()` with mandatory field validation (timestamp, user_id, source_type, event_description)
    - Implement `ingest_batch()` for batch ingestion
    - Enforce 1 MB maximum record size and supported source_type validation
    - Return structured validation failure responses with specific failing field(s)
    - _Requirements: 1.1, 1.2, 1.3_

  - [ ] 2.2 Implement buffer queue and backpressure mechanism
    - Create in-memory buffer with disk spillover for database unavailability
    - Implement 5-minute retention window with 10-second retry intervals
    - Implement backpressure: reject with HTTP 503 when buffer full or outage exceeds 5 minutes
    - Implement HTTP 429 when ingestion rate exceeds processing capacity
    - Ensure no previously accepted records are dropped during backpressure
    - _Requirements: 1.5, 1.6, 1.7_

  - [ ]* 2.3 Write unit tests for Data Collection Layer
    - Test valid record acceptance and storage
    - Test invalid record rejection with proper error messages
    - Test buffer behavior during simulated database outage
    - Test backpressure triggering and recovery
    - _Requirements: 1.1, 1.2, 1.5, 1.6, 1.7_

- [ ] 3. Implement Data Processing Pipeline
  - [ ] 3.1 Implement normalization and deduplication logic
    - Create `src/services/data_processing.py` with `DataProcessingPipeline` class
    - Implement timestamp normalization to UTC ISO 8601
    - Implement string field normalization (trim + lowercase)
    - Implement deduplication: remove duplicate (user_id, timestamp) within 5-minute lookback window
    - Process batches of up to 10,000 records within 60 seconds
    - _Requirements: 8.1_

  - [ ] 3.2 Implement field validation and quarantine mechanism
    - Reject records with missing critical fields (user_id, timestamp, activity_type) or type mismatches
    - Log rejection reasons for each rejected record
    - Implement quarantine store for records causing processing errors
    - Ensure valid records continue processing when errors occur in same batch
    - _Requirements: 8.2, 8.4_

  - [ ]* 3.3 Write property test for data normalization (Property 10)
    - **Property 10: Data normalization produces valid output format**
    - Generate random raw activity log records with various timestamp formats and string casings
    - Verify output timestamps are UTC ISO 8601, strings are trimmed and lowercased
    - Verify deduplication retains only first occurrence within 5-minute window
    - **Validates: Requirements 8.1**

  - [ ]* 3.4 Write property test for pipeline rejection (Property 11)
    - **Property 11: Processing pipeline rejects records with missing critical fields**
    - Generate records with randomly missing/malformed user_id, timestamp, or activity_type
    - Verify all such records are rejected and excluded from downstream processing
    - **Validates: Requirements 8.2**

  - [ ]* 3.5 Write property test for error isolation (Property 13)
    - **Property 13: Error isolation preserves valid record processing**
    - Generate batches with mix of valid and error-causing records
    - Verify processed_count + quarantined_count equals batch_size
    - Verify all non-error records are successfully processed
    - **Validates: Requirements 8.4**

- [ ] 4. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 5. Implement Feature Engineering Module
  - [ ] 5.1 Implement rolling window feature computation
    - Create `src/services/feature_engineering.py` with `FeatureEngineeringModule` class
    - Implement 1-hour, 8-hour, and 24-hour rolling window calculators
    - Compute mean, standard deviation, and count for each window
    - Enforce minimum 5 data points per window (omit output if fewer)
    - Recompute features at least every 5 minutes
    - _Requirements: 8.3, 8.5_

  - [ ] 5.2 Implement daily aggregate feature extraction
    - Implement `compute_daily_aggregates()` for 24-hour behavioral features
    - Extract: login time distribution, file access frequency, USB usage count, email volume, database query count, web browsing session duration
    - Implement `get_feature_vector()` to retrieve latest computed feature vector
    - Store computed feature vectors in database
    - _Requirements: 2.3_

  - [ ]* 5.3 Write property test for rolling statistical features (Property 12)
    - **Property 12: Rolling statistical features are mathematically correct**
    - Generate sets of N data points (N ≥ 5) with known statistical properties
    - Verify mean = sum/N, standard deviation = population std dev, count = N
    - Verify output is omitted when N < 5
    - **Validates: Requirements 8.3, 8.5**

  - [ ]* 5.4 Write property test for feature extraction completeness (Property 2)
    - **Property 2: Feature extraction produces all required feature categories**
    - Generate processed activity logs with at least 5 data points per 24-hour period
    - Verify output contains all required categories with non-null values
    - **Validates: Requirements 2.3**

- [ ] 6. Implement ML Anomaly Detection Engine
  - [ ] 6.1 Implement baseline manager (individual and department baselines)
    - Create `src/ml/anomaly_detection.py` with `AnomalyDetectionEngine` class
    - Implement `compute_baseline()` for individual users (requires ≥ 30 days data)
    - Implement `compute_department_baseline()` from all department users
    - Apply department baseline as fallback for users with < 30 days data
    - Implement 24-hour baseline update cycle with retry on failure (retain previous if update fails)
    - _Requirements: 2.1, 2.2, 2.4, 2.5, 2.6_

  - [ ] 6.2 Implement Isolation Forest anomaly detection and scoring
    - Configure Isolation Forest model (contamination=0.05, configurable threshold default 0.65)
    - Implement `detect_anomalies()` producing per-category anomaly scores in [0.0, 1.0]
    - Flag user as suspicious when any category exceeds threshold
    - Skip scoring for users with < 14 days data and no baseline
    - Skip scoring when activity data unavailable/incomplete (retry next cycle)
    - Support 15-minute detection cycles for up to 10,000 active users
    - _Requirements: 3.1, 3.2, 3.3, 3.5, 3.6, 3.7_

  - [ ] 6.3 Implement model training and versioning
    - Implement weekly retraining with 90-day rolling data window
    - Serve detection requests with previous model during retraining
    - Store model versions with hyperparameters and training metrics
    - Implement active model flag for version management
    - _Requirements: 3.4_

  - [ ] 6.4 Implement explainability module
    - Implement `explain_anomaly()` producing top 3 contributing factors
    - Each factor: feature name, observed value with unit, baseline average with unit
    - If fewer than 3 factors available, present all and indicate fewer identifiable
    - Annotate factors with baseline data < 7 days as limited
    - Generate explanation within 5 seconds of flagging event
    - _Requirements: 9.1, 9.2, 9.4, 9.5_

  - [ ]* 6.5 Write property test for anomaly score bounds (Property 4)
    - **Property 4: Anomaly scores are bounded within valid range**
    - Generate random valid feature vectors and pass through detection
    - Verify all output scores are in [0.0, 1.0], no NaN or infinite values
    - **Validates: Requirements 3.1**

  - [ ]* 6.6 Write property test for threshold flagging (Property 5)
    - **Property 5: Threshold flagging is consistent with anomaly scores**
    - Generate anomaly scores and configurable thresholds
    - Verify user flagged iff at least one category exceeds threshold
    - Verify scoring skipped for users with < 14 days and no baseline
    - **Validates: Requirements 3.3, 3.6**

  - [ ]* 6.7 Write property test for baseline selection (Property 3)
    - **Property 3: Baseline selection is determined by data availability**
    - Generate users with varying data availability (< 30 days, ≥ 30 days)
    - Verify individual baseline applied when ≥ 30 days, department baseline when < 30 days
    - Verify failed updates retain previous baseline unchanged
    - **Validates: Requirements 2.4, 2.6**

  - [ ]* 6.8 Write property test for anomaly explanation structure (Property 14)
    - **Property 14: Anomaly explanation structure and content**
    - Generate flagged users with varying numbers of contributing factors
    - Verify up to 3 factors with required fields (feature name, observed value/unit, baseline value/unit)
    - Verify limited data annotation when baseline < 7 days
    - **Validates: Requirements 9.1, 9.2, 9.4, 9.5**

  - [ ]* 6.9 Write property test for feature importance percentages (Property 15)
    - **Property 15: Feature importance percentages sum to 100%**
    - Generate feature importance value sets
    - Verify normalized percentages sum to 100% (±0.01% tolerance)
    - Verify all individual percentages are non-negative
    - **Validates: Requirements 9.3**

- [ ] 7. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 8. Implement Risk Scoring Engine
  - [ ] 8.1 Implement weighted risk score computation and severity classification
    - Create `src/services/risk_scoring.py` with `RiskScoringEngine` class
    - Implement `compute_risk_score()`: 0.3×login + 0.3×file_access + 0.2×network + 0.2×privilege
    - Validate input scores are in [0, 100]; reject and retain previous if any invalid/missing
    - Implement `classify_severity()`: Low (0-30), Medium (31-60), High (61-85), Critical (86-100)
    - _Requirements: 4.1, 4.2, 4.5_

  - [ ] 8.2 Implement score history and rapid change detection
    - Implement `update_user_score()` with persistence to database
    - Detect rapid change: trigger recalculation when score changes > 10 points within 24 hours
    - Update stored score within 5 seconds of detecting rapid change
    - Implement daily snapshot at 23:59 UTC to `risk_score_history` table
    - Maintain 365-day history with daily granularity
    - Implement `get_score_history()` for trend retrieval
    - _Requirements: 4.3, 4.4_

  - [ ]* 8.3 Write property test for risk score computation (Property 6)
    - **Property 6: Risk score computation follows weighted formula and range**
    - Generate random valid anomaly scores (each in [0, 100])
    - Verify result = 0.3×login + 0.3×file_access + 0.2×network + 0.2×privilege
    - Verify result is in [0, 100]
    - Verify rejection when any input is missing or outside [0, 100]
    - **Validates: Requirements 4.1, 4.5**

  - [ ]* 8.4 Write property test for severity classification (Property 7)
    - **Property 7: Severity classification matches defined ranges**
    - Generate risk scores across full [0, 100] range including boundaries (30, 31, 60, 61, 85, 86)
    - Verify Low=[0,30], Medium=[31,60], High=[61,85], Critical=[86,100]
    - Verify no ambiguity at boundary values
    - **Validates: Requirements 4.2**

  - [ ]* 8.5 Write property test for rapid score change detection (Property 8)
    - **Property 8: Rapid score change detection triggers correctly**
    - Generate sequences of risk score updates within 24-hour periods
    - Verify recalculation triggered iff absolute difference > 10 between consecutive scores
    - **Validates: Requirements 4.3**

- [ ] 9. Implement Alert System
  - [ ] 9.1 Implement alert generation and deduplication
    - Create `src/services/alert_system.py` with `AlertSystem` class
    - Implement `evaluate_and_alert()`: generate alert when risk score ≥ 31
    - Include alert fields: user_id, risk_score, severity, timestamp, triggering activity (type, source IP, timestamp)
    - Implement deduplication: update existing Open/In Review alerts instead of creating duplicates
    - Append new triggering activity evidence to existing alerts
    - _Requirements: 5.1, 5.3_

  - [ ] 9.2 Implement alert delivery with retry and dead letter queue
    - Implement `deliver_alert()` with WebSocket delivery within 30 seconds
    - Implement retry: 3 attempts at 10-second intervals on failure
    - Implement dead letter queue for persistent delivery failures
    - Generate system-level notification on exhausted retries
    - Implement `update_alert_status()` for investigation workflow
    - _Requirements: 5.2, 5.4, 5.5_

  - [ ]* 9.3 Write property test for alert generation and deduplication (Property 9)
    - **Property 9: Alert generation and deduplication**
    - Generate risk scores above and below 31 threshold
    - Verify alert generated iff score ≥ 31
    - Verify existing Open/In Review alerts updated (not duplicated) with new data
    - **Validates: Requirements 5.1, 5.3**

  - [ ]* 9.4 Write property test for dismissal reason validation (Property 21)
    - **Property 21: Dismissal reason validation**
    - Generate strings of varying lengths (0 to 600+ characters)
    - Verify acceptance iff length is between 1 and 500 characters inclusive
    - **Validates: Requirements 6.4**

- [ ] 10. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 11. Implement API Layer
  - [ ] 11.1 Implement JWT authentication and role-based authorization
    - Create `src/api/auth.py` with JWT token generation and validation
    - Implement role-based access control (Security_Analyst, Administrator)
    - Return HTTP 401 for missing/malformed/expired tokens with failure reason
    - Return HTTP 403 for insufficient role with required role specification
    - _Requirements: 10.2, 10.3, 10.4_

  - [ ] 11.2 Implement core API endpoints (alerts, risk scores, users)
    - Create `src/api/routes/` with endpoint modules
    - Implement: POST `/api/v1/logs/ingest`, POST `/api/v1/logs/ingest/batch`
    - Implement: GET `/api/v1/alerts`, GET `/api/v1/alerts/{id}`, PATCH `/api/v1/alerts/{id}/status`
    - Implement: GET `/api/v1/users/{id}/risk-score`, GET `/api/v1/users/{id}/risk-history`
    - Implement: GET `/api/v1/users/rankings` (sorted descending by risk score, max 50 per page)
    - Implement input validation returning HTTP 422 with parameter and rule identification
    - _Requirements: 10.1, 10.5, 10.6_

  - [ ] 11.3 Implement dashboard analytics and explanation endpoints
    - Implement: GET `/api/v1/dashboard/heatmap` (department × hourly time buckets)
    - Implement: GET `/api/v1/dashboard/department-analytics` (avg score, alert count, top 5 users)
    - Implement: GET `/api/v1/users/{id}/activity-summary`
    - Implement: GET `/api/v1/users/{id}/explanation/{detection_id}` (feature importance as ranked percentages)
    - Implement: POST `/api/v1/auth/token`
    - Support pagination (default 20, max 100) on all list endpoints
    - _Requirements: 7.3, 7.5, 9.3, 10.1_

  - [ ] 11.4 Implement WebSocket server for real-time alert delivery
    - Create WebSocket endpoint for dashboard real-time updates
    - Push alert notifications to connected dashboard clients
    - Implement connection management and authentication for WebSocket
    - Ensure alerts delivered within 30 seconds of generation
    - _Requirements: 5.2, 7.1_

  - [ ]* 11.5 Write property test for API pagination (Property 16)
    - **Property 16: API pagination respects bounds**
    - Generate pagination requests with varying page sizes (including None, >100, valid)
    - Verify default=20 when not specified, capped at 100, result count ≤ page size
    - **Validates: Requirements 10.1**

  - [ ]* 11.6 Write property test for API authentication/authorization (Property 17)
    - **Property 17: API authentication and authorization**
    - Generate requests with missing/malformed/expired/valid tokens and varying roles
    - Verify 401 for auth failures, 403 for role failures, success only when both pass
    - **Validates: Requirements 10.2, 10.3, 10.4**

  - [ ]* 11.7 Write property test for API input validation (Property 18)
    - **Property 18: API input validation returns structured errors**
    - Generate requests with various invalid parameters
    - Verify HTTP 422 with response identifying invalid parameter and failed rule
    - **Validates: Requirements 10.6**

  - [ ]* 11.8 Write property test for user ranking sort order (Property 19)
    - **Property 19: User ranking sort order and filtering**
    - Generate user sets with risk scores and apply random filter combinations
    - Verify results match all filters, sorted descending by risk score, correct pagination
    - **Validates: Requirements 7.1, 7.4**

  - [ ]* 11.9 Write property test for heatmap aggregation (Property 20)
    - **Property 20: Heatmap aggregation correctness**
    - Generate risk-triggering events with department and timestamp attributes
    - Verify sum of all department-hour bucket counts equals total input events in range
    - **Validates: Requirements 7.3**

- [ ] 12. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 13. Implement React Dashboard
  - [ ] 13.1 Set up React project and implement authentication UI
    - Initialize React app with TypeScript in `frontend/`
    - Install dependencies: react, react-router-dom, chart.js, react-chartjs-2, axios
    - Implement login page with JWT token management
    - Implement authenticated route guards for Security_Analyst and Administrator roles
    - _Requirements: 10.2_

  - [ ] 13.2 Implement Risk Rankings page with filtering and pagination
    - Implement paginated user list sorted by risk score descending (50 per page)
    - Implement filters: department, role, severity level (Low/Medium/High), time range (1-365 days)
    - Implement real-time updates reflecting score changes within 30 seconds
    - Implement empty state when no risk activity detected
    - Implement error state when data unavailable (show last refresh timestamp)
    - _Requirements: 7.1, 7.4, 7.6, 7.7_

  - [ ] 13.3 Implement Alert Queue and Investigation Panel
    - Implement real-time alert feed via WebSocket connection
    - Implement alert status management (Investigating, Confirmed Threat, False Positive, Resolved)
    - Implement investigation panel: triggering activity logs (up to 100), baseline deviations, risk score breakdown, 30-day timeline
    - Display top 3 contributing feature categories ranked by weight
    - Implement dismissal reason input (1-500 chars) for False Positive marking
    - Handle partial evidence unavailability with per-section error indicators
    - Ensure evidence package loads within 3 seconds
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_

  - [ ] 13.4 Implement Heat Map, Trend Charts, and Department Analytics
    - Implement heatmap: department × hourly time buckets (Chart.js matrix), configurable 1-30 day range
    - Implement 90-day risk score trend charts per user (Chart.js line charts)
    - Implement department analytics: average risk score, active alert count, top 5 highest-risk users
    - _Requirements: 7.2, 7.3, 7.5_

  - [ ]* 13.5 Write unit tests for Dashboard components
    - Test filter application and pagination logic
    - Test alert status update workflow
    - Test WebSocket connection and real-time update rendering
    - Test error and empty state displays
    - _Requirements: 7.1, 7.6, 7.7_

- [ ] 14. Implement Celery workers and scheduled tasks
  - [ ] 14.1 Implement Celery task scheduling and worker configuration
    - Create `src/workers/` with Celery app configuration and Redis broker
    - Implement scheduled tasks: 24-hour baseline update, weekly model retraining, 15-minute detection cycle, daily risk score snapshot at 23:59 UTC, 5-minute feature recomputation
    - Implement ingestion worker for buffered log processing
    - Wire ML engine tasks: baseline computation, anomaly detection, model training
    - _Requirements: 2.1, 2.2, 3.4, 3.5, 4.4, 8.3_

  - [ ]* 14.2 Write integration tests for end-to-end pipeline
    - Test full pipeline: log ingestion → processing → feature extraction → anomaly detection → risk scoring → alert generation
    - Test alert lifecycle: generation → delivery → investigation → resolution
    - Test database failover buffering and recovery
    - Use testcontainers for PostgreSQL
    - _Requirements: 1.1, 1.6, 5.1, 5.2_

- [ ] 15. Integration, wiring, and deployment configuration
  - [ ] 15.1 Wire all components together and configure deployment
    - Connect all service layers: DataCollectionService → DataProcessingPipeline → FeatureEngineeringModule → AnomalyDetectionEngine → RiskScoringEngine → AlertSystem
    - Configure FastAPI application with all route modules and middleware
    - Configure nginx reverse proxy for API and dashboard
    - Set up health check endpoints for all containers
    - Create environment configuration files (.env.example) with all required settings
    - Wire WebSocket server to alert system notifications
    - _Requirements: 1.1, 5.2, 10.1_

  - [ ]* 15.2 Write integration tests for API and WebSocket delivery
    - Test API endpoints with authenticated requests using httpx
    - Test WebSocket real-time alert delivery end-to-end
    - Test pagination, filtering, and sorting across all list endpoints
    - Test authentication and authorization flows
    - _Requirements: 10.1, 10.2, 5.2_

- [ ] 16. Final checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation after major component completions
- Property tests validate the 21 universal correctness properties defined in the design
- Unit tests validate specific examples and edge cases
- Integration tests use testcontainers for PostgreSQL and httpx for API testing
- The tech stack is Python/FastAPI (backend), React/Chart.js (frontend), PostgreSQL (database), Docker (deployment)
- Hypothesis is used for property-based testing with `@settings(max_examples=100, deadline=None)`

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1"] },
    { "id": 1, "tasks": ["1.2", "1.3"] },
    { "id": 2, "tasks": ["1.4", "2.1", "2.2"] },
    { "id": 3, "tasks": ["2.3", "3.1", "3.2"] },
    { "id": 4, "tasks": ["3.3", "3.4", "3.5", "5.1", "5.2"] },
    { "id": 5, "tasks": ["5.3", "5.4", "6.1"] },
    { "id": 6, "tasks": ["6.2", "6.3", "6.4"] },
    { "id": 7, "tasks": ["6.5", "6.6", "6.7", "6.8", "6.9"] },
    { "id": 8, "tasks": ["8.1", "8.2"] },
    { "id": 9, "tasks": ["8.3", "8.4", "8.5", "9.1", "9.2"] },
    { "id": 10, "tasks": ["9.3", "9.4", "11.1"] },
    { "id": 11, "tasks": ["11.2", "11.3", "11.4"] },
    { "id": 12, "tasks": ["11.5", "11.6", "11.7", "11.8", "11.9"] },
    { "id": 13, "tasks": ["13.1"] },
    { "id": 14, "tasks": ["13.2", "13.3", "13.4"] },
    { "id": 15, "tasks": ["13.5", "14.1"] },
    { "id": 16, "tasks": ["14.2", "15.1"] },
    { "id": 17, "tasks": ["15.2"] }
  ]
}
```
