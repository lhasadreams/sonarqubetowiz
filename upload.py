# Python 3.6+
# pip(3) install requests
import requests
import json
import time
import argparse
import os

def getconfig (config_file):
    print(config_file)
    with open(config_file, "r") as file:
        config = json.load(file)
    return config["wiz"]["client_id"], config["wiz"]["client_secret"], config["wiz"]["wiz_api_url"], config["wiz"]["wiz_url"]

def getbearer (client_id, client_secret, wiz_url):
    # Set up the URL's
    wiz_bearer_url = f"{wiz_url}/oauth/token"

    # Get a bearer token
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    # Data to send in the POST request (in this case, JSON data)
    data = {
        'grant_type': 'client_credentials',
        'audience': 'wiz-api',
        'client_id': client_id,
        'client_secret': client_secret
    }

    response = requests.post(wiz_bearer_url, data=data, headers=headers)
    response = response.json()
    token = response["access_token"]

    return(token)

def geturl (token, wiz_api_url, upload_file):
    # Set up the URL's
    wiz_graphql_url =  f"{wiz_api_url}/graphql"

    # print(f"Status Code: {response.status_code}")
    # print(token)

    # Request an S3 bucket url from Wiz
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {token}'
    }
    query = """
    query RequestSecurityScanUpload($filename: String!) {
        requestSecurityScanUpload(filename: $filename) {
            upload {
                id
                url
                systemActivityId
            }
        }
    }
    """
    variables = {
        "filename": upload_file
    }
    
    data = {
        "query": query,
        "variables": variables
    }

    response = requests.post(wiz_graphql_url, headers=headers, json=data)
    response = response.json()
    upload_url = response["data"]["requestSecurityScanUpload"]["upload"]["url"]
    systemActivityId = response["data"]["requestSecurityScanUpload"]["upload"]["systemActivityId"]

    return upload_url,systemActivityId

def uploadfiletos3 (url, upload_file):
    FILE_PATH  =  os.getcwd()+'/'+upload_file
    
    with open(FILE_PATH) as object_file:
                object_text = object_file.read()
    response = requests.put(url, data=object_text)
    if response.status_code != 200:
            raise Exception(f'Error: Received {response.status_code} status code while uploading {FILE_PATH} '
                        f'to S3 at URL: {url} ')
    print(f'Upload file succeeded\n')

def checkActivity (token, systemActivityId, wiz_api_url):
    # Set up the URL's
    wiz_graphql_url =  f"{wiz_api_url}/graphql"
    
    headers = {
        "accept": "application/json",
        "content-type": "application/json",
        "Authorization": f'Bearer {token}'
    }

    data = {
        "query": """
            query SystemActivity($id: ID!) {
                systemActivity(id: $id) {
                    id
                    status
                    statusInfo
                    result {
                        ...on SystemActivityEnrichmentIntegrationResult {
                            dataSources {
                                ... IngestionStatsDetails
                            }
                            findings {
                                ... IngestionStatsDetails
                            }
                            events {
                                ... IngestionStatsDetails
                            }
                            tags {
                                ...IngestionStatsDetails
                            }
                        }
                    }
                    context {
                        ... on SystemActivityEnrichmentIntegrationContext {
                            fileUploadId
                        }
                    }
                }
            }
            
            fragment IngestionStatsDetails on EnrichmentIntegrationStats {
                incoming
                handled
            }
        """,
        "variables": {
            "id": systemActivityId
        }
    }
    response = requests.post(wiz_graphql_url, headers=headers, json=data)
    response = response.json()
    return response

# Parse for the config file to use
def getargs():
    # Create the parser
    parser = argparse.ArgumentParser()

    # Add a switch/flag
    parser.add_argument("-c", "--config", type=str, required=True, help="Your json configuration file (required)")
    parser.add_argument("-u", "--upload", type=str, required=True, help="Your json upload file (required)")
    # Parse the arguments
    args = parser.parse_args()

    # Access the arguments
    if args.config:
        return args.config, args.upload

def main():
    # Read the arguments
    config_file, upload_file = getargs()
    # Get configuration file
    client_id, client_secret, wiz_api_url, wiz_url = getconfig(config_file)
    # Get a bearer token
    token = getbearer(client_id, client_secret, wiz_url)
    # Get an upload URL from Wiz
    UP_LOAD_URL, SYSTEM_ACTIVITY_ID = geturl(token, wiz_api_url, upload_file)
    print(f'Upload URL - '+ UP_LOAD_URL)
    # print(f'System Activity ID - '+ SYSTEM_ACTIVITY_ID)

    # Upload findings file to Wiz
    uploadfiletos3(UP_LOAD_URL,upload_file )

    # Wait for the Upload to complete before checkign for the upload status
    time.sleep(2)

    # Check the upload response
    response = checkActivity (token, SYSTEM_ACTIVITY_ID, wiz_api_url)
    print(json.dumps(response, indent=2))

if __name__ == '__main__':
    main()