import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.engine import URL
import json
import configparser

# Configuration variables
configFile = 'dash/config.ini'
section = 'dash_db'

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

    connection_url = URL.create(
        drivername='postgresql',
        username=user,
        password=password,
        host=host,
        port=port,
        database=database
    )
    engine = create_engine(connection_url, pool_recycle=3600)
    return engine

def load_json(file_path):
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return pd.json_normalize(data)
    except Exception as e:
        print(f"Error loading JSON data: {e}")
        return None

def save_to_postgres(df, table_name, engine):
    try:
        df.to_sql(table_name, engine, if_exists='append', index=False)
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

    # File path to the JSON data and table name
    json_file_path = 'dash/data.json'
    table_name = 'vulnerabilities'

    # Load JSON and transform to DataFrame
    df = load_json(json_file_path)

    # Check if the DataFrame is valid and then save it
    if df is not None and not df.empty:
        save_to_postgres(df, table_name, engine)
    else:
        print("No data to save.")
