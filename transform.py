import pandas as pd
from sqlalchemy import create_engine, text, inspect
from sqlalchemy.engine import URL
import json
import configparser
import glob
import os
import logging
import requests
from testing import test_column_names

# Configuration variables
configFile = 'dash/config.ini'
section = 'dash_db'
log_file = 'logs/mainlog.log'
os.makedirs(os.path.dirname(log_file), exist_ok = True)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(message)s',
    handlers = [
        logging.FileHandler(log_file)
    ]
)


# Function to authenticate and create an engine and create new user that is read only
def auth(configFile, section):
    config = configparser.ConfigParser()
    config.read(configFile)
    logging.info('Attempting to authenticate')
    if section not in config:
        logging.info(f'[ERROR] {configparser.NoSectionError(section)}')
        
    user = config.get(section, 'user')
    password = config.get(section, 'password')
    host = config.get(section, 'host')
    port = config.get(section, 'port')
    database = config.get(section, 'database')
    readOnlyPass = config.get(section, 'readOnlyPass')

    connection_url = URL.create(
        drivername='postgresql',
        username=user,
        password=password,
        host=host,
        port=port,
        database=database
    )
    logging.info('Attempting new connection to database')
    engine = create_engine(connection_url, pool_recycle=3600)
    logging.info(f'Established connection to {engine}')
    logging.info('Creating new user')
    try:
        with engine.connect() as connection:
            # Start a transaction
            with connection.begin():
                # Create a read-only user
                create_user_query = f"CREATE USER read_only_user WITH PASSWORD '{readOnlyPass}';"
                logging.info(f"Executing query: {create_user_query}")
                connection.execute(text(create_user_query))

                # Grant connect permission on the database
                grant_connect_query = f"GRANT CONNECT ON DATABASE {database} TO read_only_user;"
                logging.info(f"Executing query: {grant_connect_query}")
                connection.execute(text(grant_connect_query))

                # Grant usage on public schema
                grant_usage_query = "GRANT USAGE ON SCHEMA public TO read_only_user;"
                logging.info(f"Executing query: {grant_usage_query}")
                connection.execute(text(grant_usage_query))

                # Grant select on all current tables
                grant_select_query = "GRANT SELECT ON ALL TABLES IN SCHEMA public TO read_only_user;"
                logging.info(f"Executing query: {grant_select_query}")
                connection.execute(text(grant_select_query))

                # Alter default privileges
                alter_default_privileges_query = "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO read_only_user;"
                logging.info(f"Executing query: {alter_default_privileges_query}")
                connection.execute(text(alter_default_privileges_query))

        print("Read-only user created successfully.")
        logging.info('Read-only user created successfully')
    except Exception as e:
        logging.error(f"Error creating read-only user: {e}")
        print(f"Error creating read-only user: {e}")

    return engine


def load_json(file_path):
    logging.info('Loading JSON file')
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
            logging.info(f'JSON file {file_path} loaded')
        return data
    except Exception as e:
        print(f"Error loading JSON data: {e}")
        logging.info(f'[ERROR] failed to load JSON data from {file_path}')
        return None



# Fetch EPSS scores in batches
def fetch_batch_epss_scores(vulnerability_ids):
    base_url = "https://api.first.org/data/v1/epss"
    cve_query = ','.join(vulnerability_ids)
    params = {'cve': cve_query}  
    
    response = requests.get(base_url, params=params)
    if response.status_code == 200:
        epss_data = response.json().get('data', [])
        # Convert to a dictionary mapping CVEs to their EPSS scores
        epss_scores = {item['cve']: item['epss'] for item in epss_data}
        return epss_scores
    else:
        logging.error(f"EPSS API request failed with status code: {response.status_code}")
        return {}

def extract_vulnerabilities(data):
    vulnerabilities = []
    logging.info('Extracting vulnerabilities from results')

    # Collect CVEs for batch processing
    vulnerability_ids = set()
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            vulnerability_id = vuln.get('VulnerabilityID')
            if vulnerability_id:
                vulnerability_ids.add(vulnerability_id)


    epss_scores = fetch_batch_epss_scores(vulnerability_ids)

    # Process each vuln and add the EPSS score 
    for result in data.get('Results', []):
        for vuln in result.get('Vulnerabilities', []):
            vulnerability_id = vuln.get('VulnerabilityID')
            epss_score = epss_scores.get(vulnerability_id)  # Fetch score from batch result
            
            vulnerabilities.append({
                'VulnerabilityID': vulnerability_id,
                'PkgName': vuln.get('PkgName'),
                'PkgIdentifier': vuln.get('PkgIdentifier', {}).get('PURL'), 
                'InstalledVersion': vuln.get('InstalledVersion'),
                'FixedVersion': vuln.get('FixedVersion'),
                'Severity': vuln.get('Severity'),
                'EPSS_Score': epss_score 
            })

    return pd.DataFrame(vulnerabilities)


def export_all_to_excel(engine, excel_path):
    try:
        with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
            inspector = inspect(engine)
            table_names = inspector.get_table_names() 
            sheets_written = 0

            pd.DataFrame(["This file contains vulnerability data"]).to_excel(writer, sheet_name="Info", index=False)
            sheets_written += 1  

            for table_name in table_names:
                # Load data from PostgreSQL
                query = f'SELECT * FROM "{table_name}"'
                df = pd.read_sql_query(query, engine)

                if not df.empty:  # Check if DataFrame has data
                    try:
                        expected_columns = ['VulnerabilityID', 'PkgName', 'PkgIdentifier', 'InstalledVersion', 'FixedVersion', 'Severity', 'EPSS_Score']
                        test_column_names(df, expected_columns)
                        logging.info("Column names: OK")
                    except AssertionError as e:
                        logging.error(f"[ERROR] Column Name Mismatch: {e}")

   
                    df.to_excel(writer, sheet_name=table_name, index=False)
                    sheets_written += 1  
                    print(f"Data from {table_name} written to sheet '{table_name}' successfully.")
                else:
                    logging.info(f"No data found for {table_name}, skipping.")


            if sheets_written == 1: 
                raise ValueError("No data available to export. Ensure that at least one table has data.")
            
        print(f"All data exported to Excel file at {excel_path}.")
    except Exception as e:
        print(f"Error exporting to Excel: {e}")
        logging.error(f"Error exporting to Excel: {e}")




    

def save_to_postgres(df, table_name, engine):
    logging.info(f'Saving data to {table_name}')
    try:
        df.to_sql(table_name, engine, if_exists='replace', index=False)
        print(f"Data saved to {table_name} table successfully.")
        logging.info(f'Data successfully saved to {table_name}')
    except Exception as e:
        print(f"Error saving to PostgreSQL: {e}")
        logging.info(f'[ERROR] Failed to save data to {table_name}')


# Main execution
if __name__ == "__main__":
    # Authenticate and get engine
    try:
        engine = auth(configFile, section)
    except configparser.NoSectionError as e:
        print(f"Configuration section '{section}' not found in '{configFile}'.")
        #add logging
        exit(1)

    # Path pattern to find all result JSON files
    json_files = glob.glob('dash/results/*.json')

    for file_path in json_files:
        # Determine the table name based on the file name (e.g., result1, result2, etc.)
        table_name = os.path.splitext(os.path.basename(file_path))[0].lower()  # e.g., result1
        # Load JSON and extract vulnerabilities
        data = load_json(file_path)
        if data is not None:
            df = extract_vulnerabilities(data)
            
            # Check if the DataFrame is valid and then save it
            if not df.empty:
                save_to_postgres(df, table_name, engine)
            else:
                print(f"No data to save for {file_path}.")
                logging.info(f'[ERROR] No data to save for {file_path}')
        else:
            print(f"Failed to load JSON data from {file_path}.")

    excel_path = "consolidated_report.xlsx"

    export_all_to_excel(engine, excel_path)


