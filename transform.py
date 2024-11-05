import pandas as pd
from sqlalchemy import create_engine, text, Engine
from sqlalchemy.engine import URL
import json
import configparser
import glob
import os

# Configuration variables
configFile = 'dash/config.ini'
section = 'dash_db'


def create_read_only_user(engine, readOnlyPass):
    try:
        with engine.connect() as connection:
            # SQL to create a read-only user with the password from config
            query = f"""
            DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'read_only_user') THEN
                    CREATE USER read_only_user WITH PASSWORD '{readOnlyPass}';
                    GRANT CONNECT ON DATABASE vuln_db TO read_only_user;
                    GRANT USAGE ON SCHEMA public TO read_only_user;
                    GRANT SELECT ON ALL TABLES IN SCHEMA public TO read_only_user;
                    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO read_only_user;
                END IF;
            END
            $$;
            """
            connection.execute(text(query))
            print("Read-only user created or already exists.")
    except Exception as e:
        print(f"Error creating read-only user: {e}")

# Function to authenticate and create an engine
def auth(configFile, section):
    config = configparser.ConfigParser()
    config.read(configFile)

    if section not in config:
        raise configparser.NoSectionError(section)

    # Retrieve database credentials from config
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
    engine = create_engine(connection_url, pool_recycle=3600)
    create_read_only_user(engine,readOnlyPass)
    return engine

def load_json(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data
    except Exception as e:
        print(f"Error loading JSON data: {e}")
        return None

def extract_vulnerabilities(data):
    vulnerabilities = []
    # Check if the data has Results key
    if 'Results' in data:
        for result in data['Results']:
            if 'Vulnerabilities' in result:
                for vuln in result['Vulnerabilities']:
                    # Extract the required fields
                    vulnerabilities.append({
                        'VulnerabilityID': vuln.get('VulnerabilityID'),
                        'PkgName': vuln.get('PkgName'),
                        'PkgIdentifier': vuln.get('PkgIdentifier', {}).get('PURL'),  # Get PURL if it exists
                        'InstalledVersion': vuln.get('InstalledVersion'),
                        'FixedVersion': vuln.get('FixedVersion'),
                        'Severity': vuln.get('Severity')
                    })
    return pd.DataFrame(vulnerabilities)

# Function to export data to CSV
def export_to_csv(engine, query, csv_path):
    try:
        df = pd.read_sql(query, engine)
        df.to_csv(csv_path, index=False)
        print(f"Data exported to {csv_path} successfully.")
    except Exception as e:
        print(f"Error exporting to CSV: {e}")


    
def save_to_postgres(df, table_name, engine):
    try:
        df.to_sql(table_name, engine, if_exists='replace', index=False)
        print(f"Data saved to {table_name} table successfully.")
    except Exception as e:
        print(f"Error saving to PostgreSQL: {e}")



# Main execution
if __name__ == "__main__":
    # Authenticate and get engine
    try:
        
        engine = auth(configFile, section)
    except configparser.NoSectionError as e:
        print(f"Configuration section '{section}' not found in '{configFile}'.")
        exit(1)

    #Create User
    create_read_only_user(engine,readOnlyPass)

    # Path pattern to find all result JSON files
    json_files = glob.glob('dash/results/result*.json')

    for file_path in json_files:
        # Determine the table name based on the file name (e.g., result1, result2, etc.)
        table_name = os.path.splitext(os.path.basename(file_path))[0]  # e.g., result1

        # Load JSON and extract vulnerabilities
        data = load_json(file_path)
        if data is not None:
            df = extract_vulnerabilities(data)
            
            # Check if the DataFrame is valid and then save it
            if not df.empty:
                save_to_postgres(df, table_name, engine)
            else:
                print(f"No data to save for {file_path}.")
        else:
            print(f"Failed to load JSON data from {file_path}.")
    # Loop through the tables and export each to a separate Excel file
    for i in range(1, 4):
        table_name = f"result{i}"
        query = f"SELECT * FROM {table_name}"  # Query to select all data from the table
        csv_path = f"{table_name}_report.csv"  # Path for the CSV file

        # Export data to CSV
        export_to_csv(engine, query, csv_path)
