# Requirements Document

## Introduction

The Insider Threat Detection System monitors and analyzes employee, contractor, and privileged user activities to identify suspicious behavior patterns that may indicate insider threats. The system ingests user activity logs from multiple data sources, applies machine learning-based anomaly detection, computes risk scores, and surfaces alerts to security analysts through a real-time dashboard. The goal is to detect threats such as unauthorized data exfiltration, abnormal access patterns, privilege abuse, and unusual login behavior before damage occurs.

## Glossary

- **Activity_Log**: A structured record capturing a user action including timestamp, activity type, and resource accessed, stored in the Activity Logs database table.
- **Anomaly_Detection_Engine**: The machine learning component that learns normal behavior baselines and identifies deviations from those baselines using models such as Isolation Forest, Autoencoder, or One-Class SVM.
- **Alert**: A notification generated when the system detects suspicious behavior, containing the associated user, risk score, alert type, and supporting evidence.
- **Risk_Score**: A numeric value between 0 and 100 representing the threat level of a user, computed as: 0.3 × Login Anomaly + 0.3 × File Access Anomaly + 0.2 × Network Activity + 0.2 × Privilege Usage.
- **Data_Collection_Layer**: The ingestion component responsible for receiving and validating raw activity logs from multiple data sources.
- **Data_Processing_Pipeline**: The component responsible for cleaning, normalizing, and transforming raw activity logs into structured features for the Anomaly_Detection_Engine.
- **Feature_Engineering_Module**: The component that extracts behavioral features from processed activity logs, including login time patterns, file access frequency, USB usage, and network activity metrics.
- **Risk_Scoring_Engine**: The component that computes and maintains Risk_Score values for each user based on Anomaly_Detection_Engine outputs.
- **Dashboard**: The React-based web interface presenting real-time alerts, user risk rankings, heat maps, department analytics, historical trends, and investigation details to security personnel.
- **Security_Analyst**: A user role responsible for reviewing alerts, investigating suspicious behavior, and determining appropriate responses.
- **Administrator**: A user role responsible for managing system configuration and monitoring organizational risk posture.
- **Behavioral_Baseline**: A statistical model of normal activity patterns for a specific user, computed from historical Activity_Log data.
- **Data_Source**: An origin of activity logs including login/logout times, file access, USB activity, email activity, database access, and web browsing logs.

## Requirements

### Requirement 1: Activity Log Ingestion and Storage

**User Story:** As a security analyst, I want user activity logs to be collected and stored securely, so that the system has a complete audit trail for threat detection analysis.

#### Acceptance Criteria

1. WHEN Activity_Log records are received from a Data_Source, THE Data_Collection_Layer SHALL validate that each record contains all mandatory fields (timestamp, user identifier, Data_Source type, and event description) and that field values conform to their defined types, and SHALL store valid records in the Activity Logs database within 5 seconds of receipt.
2. IF an Activity_Log record fails schema validation, THEN THE Data_Collection_Layer SHALL reject the record, return a validation failure response to the originating Data_Source, and log the validation error with the originating Data_Source identifier and the specific field(s) that failed validation.
3. THE Data_Collection_Layer SHALL accept Activity_Log records from all supported Data_Source types: login times, logout times, file access, USB activity, email activity, database access, and web browsing logs, with a maximum individual record size of 1 MB.
4. THE Data_Collection_Layer SHALL store all Activity_Log records with AES-256 encryption at rest.
5. WHILE the Data_Collection_Layer is receiving logs, THE Data_Collection_Layer SHALL maintain an ingestion throughput of at least 1000 records per second.
6. IF the Activity Logs database is unavailable, THEN THE Data_Collection_Layer SHALL buffer incoming records for up to 5 minutes and retry storage at 10-second intervals, and SHALL reject new records with an error indicating storage unavailability if the buffer reaches capacity or the outage exceeds 5 minutes.
7. IF the ingestion rate exceeds the Data_Collection_Layer's processing capacity, THEN THE Data_Collection_Layer SHALL apply backpressure by rejecting new records with an error indicating capacity exceeded, without dropping or losing any previously accepted records.

### Requirement 2: Behavioral Baseline Learning

**User Story:** As a security team member, I want the system to learn normal behavior patterns for each user, so that deviations from those patterns can be detected accurately.

#### Acceptance Criteria

1. WHEN at least 30 days of Activity_Log data is available for a user, THE Anomaly_Detection_Engine SHALL compute a Behavioral_Baseline for that user within 60 minutes of the data availability threshold being met.
2. THE Anomaly_Detection_Engine SHALL update each user's Behavioral_Baseline every 24 hours by incorporating Activity_Log data from the preceding 24-hour period, completing the update within 60 minutes.
3. THE Feature_Engineering_Module SHALL extract the following behavioral features from processed Activity_Log records aggregated per 24-hour period: login time distribution, file access frequency, USB device usage count, email volume, database query count, and web browsing session duration.
4. WHEN a new user is added to the system with fewer than 30 days of Activity_Log data, THE Anomaly_Detection_Engine SHALL apply the department-level Behavioral_Baseline for the user's assigned department until at least 30 days of individual Activity_Log data is available.
5. IF a department-level Behavioral_Baseline does not exist when a new user requires one, THEN THE Anomaly_Detection_Engine SHALL generate a department-level Behavioral_Baseline from the Activity_Log data of all existing users within that department before applying it to the new user.
6. IF the 24-hour Behavioral_Baseline update fails to complete, THEN THE Anomaly_Detection_Engine SHALL retain the previous Behavioral_Baseline unchanged and retry the update within the next 60 minutes.

### Requirement 3: Anomaly Detection

**User Story:** As a security team member, I want ML-based anomaly detection to identify deviations from normal behavior, so that potential insider threats are flagged automatically.

#### Acceptance Criteria

1. WHEN the Anomaly_Detection_Engine processes a user's current Activity_Log data, THE Anomaly_Detection_Engine SHALL compare the activity against the user's Behavioral_Baseline and output an anomaly score between 0.0 (normal) and 1.0 (highly anomalous) for each feature category.
2. THE Anomaly_Detection_Engine SHALL use the Isolation Forest algorithm as the primary detection model.
3. WHEN a user's anomaly score exceeds the configured threshold (default: 0.65, configurable range: 0.1 to 0.95) in any feature category, THE Anomaly_Detection_Engine SHALL flag the user's activity as suspicious and forward the detection, including the anomaly score and triggering feature category, to the Risk_Scoring_Engine.
4. THE Anomaly_Detection_Engine SHALL retrain the detection model weekly using the latest 90 days of Activity_Log data, and SHALL continue serving detection requests using the previous model version until retraining completes successfully.
5. THE Anomaly_Detection_Engine SHALL process all active users' Activity_Log data within a 15-minute detection cycle for up to 10,000 active users.
6. IF a user has fewer than 14 days of Activity_Log data and no established Behavioral_Baseline exists, THEN THE Anomaly_Detection_Engine SHALL skip anomaly scoring for that user and log the user as pending baseline establishment.
7. IF Activity_Log data for a user is unavailable or incomplete during a detection cycle, THEN THE Anomaly_Detection_Engine SHALL skip scoring for that user for the current cycle, record a data-unavailability event, and retry in the next detection cycle.

### Requirement 4: Risk Score Computation

**User Story:** As a security analyst, I want each alert to include a computed risk score, so that I can prioritize my investigation efforts effectively.

#### Acceptance Criteria

1. WHEN the Risk_Scoring_Engine receives anomaly scores from the Anomaly_Detection_Engine, THE Risk_Scoring_Engine SHALL compute a Risk_Score using the formula: 0.3 × Login Anomaly + 0.3 × File Access Anomaly + 0.2 × Network Activity + 0.2 × Privilege Usage, where each individual anomaly score is a value in the range 0 to 100 inclusive, producing a Risk_Score in the range 0 to 100.
2. THE Risk_Scoring_Engine SHALL classify Risk_Score values into three severity levels: Low (0-30 inclusive), Medium (31-60 inclusive), and High (61-100 inclusive).
3. WHEN a user's Risk_Score changes by more than 10 points within a 24-hour period, THE Risk_Scoring_Engine SHALL trigger a recalculation and update the stored Risk_Score within 5 seconds of detecting the change.
4. THE Risk_Scoring_Engine SHALL maintain a historical record of each user's Risk_Score captured as an end-of-day snapshot at 23:59 UTC, with daily granularity for at least 365 days.
5. IF one or more anomaly scores are missing or outside the valid range of 0 to 100 when received by the Risk_Scoring_Engine, THEN THE Risk_Scoring_Engine SHALL reject the computation, retain the previously stored Risk_Score for the user, and log an error message indicating which anomaly scores were invalid.

### Requirement 5: Alert Generation

**User Story:** As a security analyst, I want the system to generate alerts for suspicious behavior, so that potential threats are brought to my attention promptly.

#### Acceptance Criteria

1. WHEN a user's Risk_Score reaches or exceeds the Medium severity threshold (31), THE Alert System SHALL generate an Alert containing the user identifier, current Risk_Score, severity level (Medium: 31–60, High: 61–85, Critical: 86–100), timestamp of generation, and the triggering activity (activity type, source IP, and timestamp of the activity that caused the threshold breach).
2. WHEN an Alert is generated, THE Alert System SHALL deliver the Alert to the Dashboard within 30 seconds of generation.
3. WHEN an Alert is generated for a user who has an existing Alert in "Open" or "In Review" status, THE Alert System SHALL update the existing Alert with the new Risk_Score, recalculated severity level, and append the new triggering activity evidence rather than creating a duplicate Alert.
4. IF the Alert System fails to deliver an Alert to the Dashboard, THEN THE Alert System SHALL retry delivery three times at 10-second intervals and log the delivery failure.
5. IF the Alert System fails to deliver an Alert after all three retry attempts, THEN THE Alert System SHALL persist the undelivered Alert to a durable queue and generate a system-level notification indicating delivery failure for that Alert.

### Requirement 6: Alert Investigation and Evidence Display

**User Story:** As a security analyst, I want to view supporting evidence when reviewing an alert, so that I can make informed decisions about the threat.

#### Acceptance Criteria

1. WHEN a Security_Analyst selects an Alert for review, THE Dashboard SHALL display the evidence package including: the triggering Activity_Log entries (up to the 100 most recent entries), the user's Behavioral_Baseline deviations, the Risk_Score breakdown by category, and a timeline of activities from the preceding 30 days.
2. WHEN a Security_Analyst selects an Alert, THE Dashboard SHALL display the Anomaly_Detection_Engine's explanation of why the user was flagged, including the top 3 feature categories that contributed to the anomaly score ranked by contribution weight.
3. THE Dashboard SHALL allow the Security_Analyst to update the Alert status to one of: Investigating, Confirmed Threat, False Positive, or Resolved.
4. WHEN a Security_Analyst marks an Alert as False Positive, THE Dashboard SHALL require a dismissal reason between 1 and 500 characters and feed the correction back to the Anomaly_Detection_Engine for model improvement.
5. IF evidence data is partially or fully unavailable when a Security_Analyst selects an Alert, THEN THE Dashboard SHALL display the available evidence sections and show an error indication for each unavailable section, identifying which data could not be loaded.
6. WHEN a Security_Analyst selects an Alert for review, THE Dashboard SHALL display the evidence package within 3 seconds of the selection action.

### Requirement 7: Risk Dashboard and User Ranking

**User Story:** As an administrator, I want a dashboard showing risky users ranked by risk score, so that I can monitor organizational security posture at a glance.

#### Acceptance Criteria

1. THE Dashboard SHALL display a paginated ranked list of all monitored users ordered by Risk_Score in descending order, showing no more than 50 users per page, with data reflecting Risk_Score changes within 30 seconds of occurrence.
2. THE Dashboard SHALL display Risk_Score trend charts for each user showing daily Risk_Score values over the past 90 days.
3. THE Dashboard SHALL provide a heat map visualization showing the count of events that triggered Risk_Score increases, aggregated by department and by hourly time buckets over a configurable range of 1 to 30 days.
4. THE Dashboard SHALL support filtering the user risk ranking by department, role, risk severity level (Low: 0–30, Medium: 31–60, High: 61–100), and time range (minimum 1 day, maximum 365 days).
5. THE Dashboard SHALL display department-level aggregate risk analytics including average Risk_Score, count of active Alerts, and the top 5 highest-risk users per department.
6. IF the Dashboard fails to retrieve risk data from the data source, THEN THE Dashboard SHALL display an error indication stating that data is temporarily unavailable and show the timestamp of the last successful data refresh.
7. IF no monitored users exist or all Risk_Scores are zero, THEN THE Dashboard SHALL display an empty state indication communicating that no risk activity has been detected.

### Requirement 8: Data Processing and Feature Engineering

**User Story:** As a security team member, I want raw activity logs to be processed into meaningful behavioral features, so that the anomaly detection engine receives high-quality input data.

#### Acceptance Criteria

1. WHEN raw Activity_Log records are received, THE Data_Processing_Pipeline SHALL normalize field formats (timestamps to UTC ISO 8601, string fields trimmed and lowercased), remove records with duplicate user_id and timestamp combinations within a 5-minute lookback window, and complete processing within 60 seconds of ingestion for batches of up to 10,000 records.
2. IF a record contains missing critical fields (user_id, timestamp, or activity_type) or fields that do not conform to their expected data type, THEN THE Data_Processing_Pipeline SHALL reject the record, log the rejection reason, and exclude it from downstream processing.
3. THE Feature_Engineering_Module SHALL compute rolling statistical features (mean, standard deviation, count) over 1-hour, 8-hour, and 24-hour windows for each user's activity metrics (event count, distinct activity types, and session duration), recomputing at least every 5 minutes, and requiring a minimum of 5 data points in a window before producing output for that window.
4. WHEN the Data_Processing_Pipeline encounters a processing error not covered by field-level validation in criterion 2, THE Data_Processing_Pipeline SHALL quarantine the affected records in a dedicated store, log the error type and record identifiers, and continue processing remaining records without interruption.
5. IF the Feature_Engineering_Module has fewer than 5 data points within a rolling window for a given user, THEN THE Feature_Engineering_Module SHALL omit feature output for that window and indicate insufficient data for that user-window combination.

### Requirement 9: System Explainability

**User Story:** As a security analyst, I want the system to explain why a user was flagged, so that I can understand the reasoning behind each alert and validate the detection.

#### Acceptance Criteria

1. WHEN the Anomaly_Detection_Engine flags a user, THE Anomaly_Detection_Engine SHALL produce a plain-language explanation listing the top three contributing factors to the anomaly score within 5 seconds of the flagging event.
2. THE Anomaly_Detection_Engine SHALL express each contributing factor as a comparison between the observed value and the Behavioral_Baseline expected value, including the feature name, the observed numeric value with unit, and the baseline average value with unit (e.g., "File downloads: 47 today vs. baseline average of 5 per day").
3. WHEN a Security_Analyst requests detailed explanation for an Alert, THE Dashboard SHALL display the feature importance values from the Isolation Forest model for that detection instance as a ranked list of all features with their normalized importance scores expressed as percentages summing to 100%.
4. IF the Anomaly_Detection_Engine cannot determine at least three contributing factors for a flagged user, THEN THE Anomaly_Detection_Engine SHALL present all available contributing factors and indicate that fewer than three factors were identifiable.
5. IF the Behavioral_Baseline contains fewer than 7 days of historical data for a contributing factor, THEN THE Anomaly_Detection_Engine SHALL annotate that factor's comparison with an indication that the baseline is based on limited data.

### Requirement 10: API Layer

**User Story:** As a developer, I want a RESTful API layer for the system, so that the frontend dashboard and external integrations can access threat detection data programmatically.

#### Acceptance Criteria

1. THE API Layer SHALL expose RESTful endpoints using FastAPI for retrieving Alerts, Risk_Scores, user Activity_Log summaries, and dashboard analytics data, with list endpoints supporting pagination with a default page size of 20 and a maximum page size of 100.
2. THE API Layer SHALL authenticate all requests using JWT tokens and authorize access based on the requesting user's role (Security_Analyst or Administrator).
3. IF a request contains a missing, malformed, or expired JWT token, THEN THE API Layer SHALL return an HTTP 401 response with an error message indicating the authentication failure reason.
4. IF the authenticated user is not authorized to access the requested resource, THEN THE API Layer SHALL return an HTTP 403 response with an error message specifying the required role.
5. WHILE serving fewer than 100 concurrent users, THE API Layer SHALL respond to all read requests within 500 milliseconds at the 95th percentile.
6. THE API Layer SHALL validate all input parameters and return HTTP 422 responses with error messages that identify the invalid parameter and the validation rule that failed.
