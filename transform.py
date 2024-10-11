import psycopg2
import json
import os
from datetime import datetime

# Get database password from environment variables (set in GitLab CI)
pg_pass = os.environ.get('PG_PASS')

# Database connection
try:
    conn = psycopg2.connect(dbname="vuln_db", user="service_account", password=pg_pass, host="postgres", port="5432", options="-c search_path=public")
    cursor = conn.cursor()
    print(f"Data base connected scuessfully")
except psycopg2.Error as e:
    print(f"Database connection error: {e}")
    exit(1)

cursor.execute("SHOW search_path;")
search_path = cursor.fetchone()[0]
print(f"Current search path: {search_path}")

# Check if the table exists
try:
    cursor.execute("SELECT * FROM repositories LIMIT 1;")
    print("Table repositories is accessible.")
except psycopg2.Error as e:
    print(f"Error accessing table: {e}")
    conn.close()
    exit(1)


# Directory where Trivy results are stored (absolute path)
scan_output_dir = '/builds/darkskelly/dash/trivy-results'

# Helper function to insert repo into database
def insert_repo(repo_name):
    cursor.execute("INSERT INTO repositories (repo_name) VALUES (%s) ON CONFLICT (repo_name) DO NOTHING RETURNING repo_id", (repo_name,))
    result = cursor.fetchone()
    if result:
        return result[0]
    else:
        cursor.execute("SELECT repo_id FROM repositories WHERE repo_name = %s", (repo_name,))
        return cursor.fetchone()[0]

# Parse each Trivy JSON file and insert vulnerabilities into DB
for file in os.listdir(scan_output_dir):
    if file.endswith("-trivy-report.json"):
        repo_name = file.split("-trivy-report")[0]
        repo_id = insert_repo(repo_name)

        with open(os.path.join(scan_output_dir, file)) as f:
            data = json.load(f)
            for result in data['Results']:
                for vuln in result.get('Vulnerabilities', []):
                    cve_id = vuln['VulnerabilityID']
                    severity = vuln['Severity']
                    package_name = vuln['PkgName']
                    description = vuln.get('Description', 'No description provided')
                    detected_on = datetime.now()

                    cursor.execute("""
                        INSERT INTO vulnerabilities (repo_id, cve_id, severity, package_name, vulnerability_description, detected_on)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (repo_id, cve_id, severity, package_name, description, detected_on))

# Commit the changes and close the connection
conn.commit()
conn.close()
