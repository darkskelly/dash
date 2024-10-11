CREATE TABLE IF NOT EXISTS repositories (
    repo_id SERIAL PRIMARY KEY,
    repo_name VARCHAR(255) UNIQUE NOT NULL
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    vuln_id SERIAL PRIMARY KEY,
    repo_id INTEGER REFERENCES repositories(repo_id),
    cve_id VARCHAR(50),
    severity VARCHAR(50),
    package_name VARCHAR(255),
    vulnerability_description TEXT,
    detected_on TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
