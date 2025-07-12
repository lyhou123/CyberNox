-- CyberNox Database Initialization Script
-- Creates necessary tables and initial data

-- Create database user if not exists
DO
$do$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles
      WHERE  rolname = 'cybernox') THEN

      CREATE ROLE cybernox LOGIN PASSWORD 'cybernox-secure-password';
   END IF;
END
$do$;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE cybernox TO cybernox;

-- Create schemas
CREATE SCHEMA IF NOT EXISTS cybernox_data;
CREATE SCHEMA IF NOT EXISTS cybernox_reports;
CREATE SCHEMA IF NOT EXISTS cybernox_logs;

-- Set search path
ALTER DATABASE cybernox SET search_path TO cybernox_data, cybernox_reports, cybernox_logs, public;

-- Create tables for scan results
CREATE TABLE IF NOT EXISTS cybernox_data.scan_results (
    id SERIAL PRIMARY KEY,
    scan_type VARCHAR(50) NOT NULL,
    target VARCHAR(255) NOT NULL,
    results JSONB,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(100),
    status VARCHAR(20) DEFAULT 'completed'
);

-- Create table for vulnerability assessments
CREATE TABLE IF NOT EXISTS cybernox_data.vulnerability_assessments (
    id SERIAL PRIMARY KEY,
    target VARCHAR(255) NOT NULL,
    assessment_type VARCHAR(50) NOT NULL,
    vulnerabilities JSONB,
    risk_score INTEGER,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(100)
);

-- Create table for reports
CREATE TABLE IF NOT EXISTS cybernox_reports.reports (
    id SERIAL PRIMARY KEY,
    report_name VARCHAR(255) NOT NULL,
    report_type VARCHAR(50) NOT NULL,
    content JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    user_id VARCHAR(100)
);

-- Create table for system logs
CREATE TABLE IF NOT EXISTS cybernox_logs.activity_logs (
    id SERIAL PRIMARY KEY,
    action VARCHAR(100) NOT NULL,
    details JSONB,
    user_id VARCHAR(100),
    ip_address INET,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity VARCHAR(20) DEFAULT 'info'
);

-- Create table for API sessions
CREATE TABLE IF NOT EXISTS cybernox_data.api_sessions (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(255) UNIQUE NOT NULL,
    user_id VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address INET
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_scan_results_timestamp ON cybernox_data.scan_results(timestamp);
CREATE INDEX IF NOT EXISTS idx_scan_results_target ON cybernox_data.scan_results(target);
CREATE INDEX IF NOT EXISTS idx_vuln_assessments_timestamp ON cybernox_data.vulnerability_assessments(timestamp);
CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON cybernox_logs.activity_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_api_sessions_session_id ON cybernox_data.api_sessions(session_id);

-- Grant permissions to cybernox user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA cybernox_data TO cybernox;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA cybernox_reports TO cybernox;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA cybernox_logs TO cybernox;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA cybernox_data TO cybernox;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA cybernox_reports TO cybernox;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA cybernox_logs TO cybernox;

-- Insert initial admin user (optional)
INSERT INTO cybernox_data.api_sessions (session_id, user_id, expires_at) 
VALUES ('admin-session-' || generate_random_uuid(), 'admin', CURRENT_TIMESTAMP + INTERVAL '30 days')
ON CONFLICT DO NOTHING;
