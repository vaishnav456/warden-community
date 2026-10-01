-- ISOLATED DISPOSABLE DATABASE ONLY.
CREATE EXTENSION pgcrypto;
CREATE ROLE service_role;
CREATE SCHEMA endpt;
CREATE TABLE endpt.companies(id uuid PRIMARY KEY);
CREATE TABLE endpt.admin_users(id uuid PRIMARY KEY);
CREATE TABLE endpt.build_requests(id uuid PRIMARY KEY);
CREATE TABLE endpt.endpoints(id uuid PRIMARY KEY,company_id uuid REFERENCES endpt.companies,branch_id uuid);
CREATE TABLE endpt.home_spaces(id uuid PRIMARY KEY);
CREATE TABLE endpt.jobs(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),company_id uuid,branch_id uuid,endpoint_id uuid,type text,payload text,status text,created_by uuid);
INSERT INTO endpt.companies VALUES('00000000-0000-0000-0000-000000000001');
INSERT INTO endpt.build_requests VALUES('00000000-0000-0000-0000-000000000002');
INSERT INTO endpt.endpoints VALUES('00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000001',NULL);
