/* ============================================================
   PROJECT: Linux Authentication & IAM Security Analytics
   DATABASE: iam_security_analytics
   DATASET: linux_auth_logs_labeled.csv
   FINAL DATASET SIZE: 500,000 records

   PURPOSE:
   Import Linux authentication logs into MySQL and perform
   security-focused analysis related to authentication,
   anomalies, account risk, and network activity.
   ============================================================ */
   
   /* ============================================================
   SECTION 1: DATABASE SELECTION
   ============================================================ */

-- Select the IAM Security Analytics database for this project.
USE iam_security_analytics;

/* ============================================================
   SECTION 2: CREATE FULL DATASET TABLE
   ============================================================ */

-- Create a new table using the same structure as the existing
-- Linux authentication log table.
-- This creates the table structure without copying the data.
CREATE TABLE linux_auth_logs_full
LIKE linux_auth_logs;

-- Display all tables in the current database to verify that
-- linux_auth_logs_full was created successfully.
show tables;

/* ============================================================
   SECTION 3: ENABLE LOCAL FILE IMPORT
   ============================================================ */

-- Check whether the MySQL server allows LOCAL file loading.
SHOW GLOBAL VARIABLES LIKE 'local_infile';
-- Enable LOCAL file loading at the MySQL server level.
SET GLOBAL local_infile = ON;

-- Re-select the project database.
use iam_security_analytics;

-- Verify that LOCAL file loading is enabled.
SHOW GLOBAL VARIABLES LIKE 'local_infile';

/* ============================================================
   SECTION 4: PREPARE TABLE FOR DATA IMPORT
   ============================================================ */

-- Remove any existing records from the full dataset table
-- before importing the CSV.
-- This prevents duplicate records during a fresh import.
TRUNCATE TABLE linux_auth_logs_full;

/* ============================================================
   SECTION 5: IMPORT LINUX AUTHENTICATION DATA
   ============================================================ */

-- Import the Linux authentication dataset from the CSV file.
-- The first row contains column headers, so it is skipped.
-- Commas separate the fields and double quotes identify
-- text fields.
--
-- NOTE:
-- The successful import used '\n' for line termination and
-- loaded 500,000 records.
LOAD DATA LOCAL INFILE 'C:/Users/abhir/OneDrive/Documents/Desktop/IAM_Access_Risk_Analytics/1_Raw Data/linux_auth_logs_labeled.csv'
INTO TABLE linux_auth_logs_full
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\r\n'
IGNORE 1 ROWS;
LOAD DATA LOCAL INFILE 'C:/Users/abhir/OneDrive/Documents/Desktop/IAM_Access_Risk_Analytics/1_Raw Data/linux_auth_logs_labeled.csv'
INTO TABLE linux_auth_logs_full
FIELDS TERMINATED BY ','
ENCLOSED BY '"'
LINES TERMINATED BY '\n'
IGNORE 1 ROWS;

USE iam_security_analytics;

/* ============================================================
   SECTION 6: DATA VALIDATION
   ============================================================ */

-- Verify the total number of records imported into MySQL.
-- Expected result: 500,000 records.
SELECT COUNT(*) AS total_records
FROM linux_auth_logs_full;

/* ============================================================
   SECTION 7: AUTHENTICATION STATUS ANALYSIS
   ============================================================ */

-- Count successful and failed authentication events.
-- This provides a high-level view of authentication activity.
SELECT
    status,
    COUNT(*) AS event_count
FROM linux_auth_logs_full
GROUP BY status;

/* ============================================================
   SECTION 8: ANOMALY DISTRIBUTION
   ============================================================ */

-- Count authentication events by anomaly category.
-- This identifies how many events are labelled as normal
-- or associated with specific security anomalies.
SELECT
    anomaly_label,
    COUNT(*) AS event_count
FROM linux_auth_logs_full
GROUP BY anomaly_label
ORDER BY event_count DESC;

/* ============================================================
   SECTION 9: TOP USERS WITH FAILED LOGINS
   ============================================================ */

-- Identify the top 10 user accounts with the highest number
-- of failed authentication events.
--
-- Security purpose:
-- Accounts with repeated failed logins may require additional
-- investigation for possible credential attacks or misuse.
SELECT
    username,
    COUNT(*) AS failed_logins
FROM linux_auth_logs_full
WHERE status = 'Failed'
GROUP BY username
ORDER BY failed_logins DESC
LIMIT 10;

/* ============================================================
   SECTION 10: TOP SOURCE IPs WITH FAILED LOGINS
   ============================================================ */

-- Identify the top 10 source IP addresses associated with
-- failed authentication events.
--
-- Security purpose:
-- Helps identify source addresses generating repeated
-- authentication failures.
SELECT
    source_ip,
    COUNT(*) AS failed_logins
FROM linux_auth_logs_full
WHERE status = 'Failed'
GROUP BY source_ip
ORDER BY failed_logins DESC
LIMIT 10;

/* ============================================================
   SECTION 11: PRIVILEGE ESCALATION EVENT INVESTIGATION
   ============================================================ */

-- Display sample events labelled as privilege escalation.
--
-- This provides detailed investigation information including
-- the affected user, source IP, server, service, status,
-- attempts, and protocol.
SELECT
    username,
    source_ip,
    server,
    service,
    status,
    attempts,
    protocol
FROM linux_auth_logs_full
WHERE anomaly_label = 'privilege_escalation'
LIMIT 20;

/* ============================================================
   SECTION 12: PRIVILEGE ESCALATION BY USER
   ============================================================ */

-- Identify the top 10 user accounts associated with
-- privilege escalation events.
--
-- Security purpose:
-- Helps identify accounts that appear frequently in
-- privilege-related security events.
SELECT
    username,
    COUNT(*) AS privilege_escalation_events
FROM linux_auth_logs_full
WHERE anomaly_label = 'privilege_escalation'
GROUP BY username
ORDER BY privilege_escalation_events DESC
LIMIT 10;

/* ============================================================
   SECTION 13: BRUTE FORCE ACTIVITY BY USER
   ============================================================ */

-- Identify the top 10 user accounts associated with
-- events labelled as brute force.
--
-- Security purpose:
-- Helps identify accounts that may be targeted by
-- repeated authentication attacks.
SELECT
    username,
    COUNT(*) AS brute_force_events
FROM linux_auth_logs_full
WHERE anomaly_label = 'brute_force'
GROUP BY username
ORDER BY brute_force_events DESC
LIMIT 10;

/* ============================================================
   SECTION 14: GEO ANOMALY BY USER
   ============================================================ */

-- Identify the top 10 user accounts associated with
-- geographic anomaly events.
--
-- Security purpose:
-- Helps highlight accounts involved in authentication
-- events that have been labelled as geographic anomalies.
SELECT
    username,
    COUNT(*) AS geo_anomaly_events
FROM linux_auth_logs_full
WHERE anomaly_label = 'geo_anomaly'
GROUP BY username
ORDER BY geo_anomaly_events DESC
LIMIT 10;

/* ============================================================
   SECTION 15: PORT SCAN ACTIVITY BY USER
   ============================================================ */

-- Identify the top 10 user accounts associated with
-- events labelled as port scanning.
--
-- Security purpose:
-- Helps identify accounts involved in network-related
-- security anomalies.
SELECT
    username,
    COUNT(*) AS port_scan_events
FROM linux_auth_logs_full
WHERE anomaly_label = 'port_scan'
GROUP BY username
ORDER BY port_scan_events DESC
LIMIT 10;

/* ============================================================
   SECTION 16: PORT SCAN NETWORK CONTEXT
   ============================================================ */

-- Analyze port scan events by server, destination port,
-- and protocol.
--
-- Security purpose:
-- Provides network context for events labelled as
-- port scanning activity.
SELECT
    server,
    port,
    protocol,
    COUNT(*) AS port_scan_events
FROM linux_auth_logs_full
WHERE anomaly_label = 'port_scan'
GROUP BY
    server,
    port,
    protocol
ORDER BY port_scan_events DESC
LIMIT 15;

/* ============================================================
   SECTION 17: HIGH-RISK USER ACCOUNT ANALYSIS
   ============================================================ */

-- Calculate security activity for each user account.
--
-- The project uses a custom risk scoring model:
--
-- Failed Login              = 1 point
-- Brute Force Event         = 5 points
-- Privilege Escalation      = 5 points
-- Geo Anomaly               = 3 points
-- Port Scan                 = 3 points
--
-- NOTE:
-- This is a project-defined analytical scoring model.
-- It is not an industry-standard IAM risk score.
SELECT
    username,

    SUM(
        CASE
            WHEN status = 'Failed' THEN 1
            ELSE 0
        END
    ) AS failed_logins,

    SUM(
        CASE
            WHEN anomaly_label = 'brute_force' THEN 1
            ELSE 0
        END
    ) AS brute_force_events,

    SUM(
        CASE
            WHEN anomaly_label = 'privilege_escalation' THEN 1
            ELSE 0
        END
    ) AS privilege_escalation_events,

    SUM(
        CASE
            WHEN anomaly_label = 'geo_anomaly' THEN 1
            ELSE 0
        END
    ) AS geo_anomaly_events,

    SUM(
        CASE
            WHEN anomaly_label = 'port_scan' THEN 1
            ELSE 0
        END
    ) AS port_scan_events,

    (
        SUM(CASE WHEN status = 'Failed' THEN 1 ELSE 0 END)
        + SUM(CASE WHEN anomaly_label = 'brute_force' THEN 1 ELSE 0 END) * 5
        + SUM(CASE WHEN anomaly_label = 'privilege_escalation' THEN 1 ELSE 0 END) * 5
        + SUM(CASE WHEN anomaly_label = 'geo_anomaly' THEN 1 ELSE 0 END) * 3
        + SUM(CASE WHEN anomaly_label = 'port_scan' THEN 1 ELSE 0 END) * 3
    ) AS risk_score

FROM linux_auth_logs_full

GROUP BY username

ORDER BY risk_score DESC

LIMIT 10;
/* ============================================================
   END OF SQL SECURITY ANALYSIS
   ============================================================ */