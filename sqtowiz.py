import requests
import json
from datetime import datetime, timezone
import argparse
import os
import time

# Read the config.json file
def getconfig (config_file):
    with open(config_file, "r") as file:
        config = json.load(file)
    return config["sonarqube"], config["wiz"]

def get_project_keys(sonarqube_url, auth_key, organization):
    url = f"{sonarqube_url}/api/projects/search"
    headers = {
        "Authorization": f"Bearer {auth_key}"
    }
    project_keys = []

    # SonarQube API supports pagination
    page = 1
    page_size = 100
    while True:
        params = {"p": page, "ps": page_size, "organization": organization}
        response = requests.get(url, headers=headers, params=params)

        if response.status_code != 200:
            print(f"Error: Unable to fetch projects. Status code: {response.status_code}")
            print(response.json())
            return []

        data = response.json()
        for project in data.get("components", []):
            project_keys.append(project["key"])

        if data["paging"]["total"] <= page * page_size:
            break
        page += 1

    return project_keys

# Convert the SonarQube input into a file to uplaod to Wiz
def convert(sonarqube_url, auth_key, project_key, integrationId):
    auth = (auth_key, "")

    # Fetch Issues with CWE References
    issues_url = f"{sonarqube_url}/api/issues/search"
    rules_url = f"{sonarqube_url}/api/rules/show"

    params = {
        "componentKeys": project_key,
        "types": "VULNERABILITY",  # Look for vulnerabilities
        "ps": 500,  # Page size
        "p": 1      # Page number
    }

    # Get all the issues from SonarQube - does not take into account any pagination required, we wil just take the first 500 issues in each repo.
    sonarquberesponse = requests.get(issues_url, auth=auth, params=params)

    # Do we have any CWE's from SonarQube?
    if sonarquberesponse.status_code == 200:
        # Convert the response into a data dictionary
        sonarqube_json = sonarquberesponse.json()

        # Create the Wiz required json response
        responsejson = {}

        # Add the Top Level Integration ID
        # responsejson["integrationId"] = "55c176cc-d155-43a2-98ed-aa56873a1ca1"
        responsejson["integrationId"] = integrationId

        # Add the top Level dataSources array to the Wiz Response
        responsejson["dataSources"] = []

        # Create a correctly formatted time stamp for the Wiz response
        now = (datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"))

        # Add id, analysis date and the assests array to the Wiz Response
        datasources = {"id": project_key, "analysisDate": now,"assets": []}
        responsejson["dataSources"].append(datasources)

        # Add the assest and webAppVulnerabilityFindings Array to the Wiz Response
        project, repo = project_key.split("_", 1)
        newasset = {"assetIdentifier": {"cloudPlatform": "GitHub", "providerId":"github.com##"+project+"/"+repo+"##main"},"webAppVulnerabilityFindings": []}
        responsejson["dataSources"][0]["assets"].append(newasset)

        # Read the SonarQube Issues
        issues = sonarqube_json.get("issues",[])
        if not issues:
            print("No SonarQube issues found.")
            return responsejson, "false"
        else:
            print(f"Found {len(issues)} vulnerabilities.")
            # print(json.dumps(issues, indent=2))
            # exit(0)

        # Iterate over the SonarQube Issues, find the CWE's and add them the Wiz Response
        for issue in issues:
            rule_key = issue["rule"]
            params2 = {
                "key": rule_key,
                "organization": "lhasadreams"
            }
            # Fetch rule details to get CWE
            rule_response = requests.get(rules_url, auth=auth, params=params2)
            if rule_response.status_code == 200:
                rule_details = rule_response.json()["rule"]
                # cwes = rule_details.get("securityStandards")
                # print(f"Issue: {issue['message']} (CWE: {cwes if cwes else 'N/A'})")

                # Build up the response
                commitHash = issue["hash"]
                filename = issue["component"].split(":", 1)[1]
                linenumbers = str(issue["textRange"]["startLine"]) + "-" + str(issue["textRange"]["endLine"])
                id = issue["key"]
                name = "CWE-" + rule_details["securityStandards"][0].split(":", 1)[1]
                severity = convert_severity(rule_details["severity"])
                detailedName = rule_details["name"]
                externalFindingLink = sonarqube_url+"/project/issues?id="+project_key+"&open="+id
                source = "SonarQube"
                remediation = issue["message"]
                sastfinding = {"sastFinding":{"commitHash":commitHash,"filename":"/"+filename,"lineNumbers":linenumbers},"id": id ,"name": name,"detailedName": detailedName,"severity": severity,"externalFindingLink": externalFindingLink,"source": source,"remediation": remediation}
                responsejson["dataSources"][0]["assets"][0]["webAppVulnerabilityFindings"].append(sastfinding)
            else:
                print(f"Failed to fetch rule details for {rule_key}")
    else:
        print(f"Error: {sonarquberesponse.status_code} - {sonarquberesponse.text}")
    
    return responsejson, "true"

# Write the wiz.json file to disk
def writejsonfile(responsejson, project_key):
    filename = "wiz_upload_"+project_key+".json"
    with open(filename, 'w') as file:
        json.dump(responsejson, file, indent=4)

# Convert from SonarQube security levels to Wiz ones
def convert_severity(sonarqube_severity):
    severity_mapping = {
        "BLOCKER": "Critical",
        "CRITICAL": "High",
        "MAJOR": "Medium",
        "MINOR": "Low",
        "INFO": "Info"
    }
    return severity_mapping.get(sonarqube_severity.upper(), "Unknown")

# Parse for the config file to use
def getargs():
    # Create the parser
    parser = argparse.ArgumentParser()

    # Add a switch/flag
    parser.add_argument("-c", "--config", type=str, required=True, help="Your json configuration file (required)")

    # Parse the arguments
    args = parser.parse_args()

    # Access the arguments
    if args.config:
        return args.config
    
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

def main():
    # Read the arguments
    config_file = getargs()
    # Check that the file exists
    if not os.path.isfile(config_file):
        print(f"Error: The file '{config_file}' does not exist.")
        exit(1)
    # Read the config file
    sonarqube, wiz = getconfig (config_file)

    # Get a bearer token
    token = getbearer(wiz["client_id"], wiz["client_secret"], wiz["wiz_url"])

    # Get the list of SonarQube projects
    project_keys = get_project_keys(sonarqube["sonarqube_url"], sonarqube["auth_key"], sonarqube["organization"])
    print("SonarQube Project Keys:")
    for key in project_keys:
        print(key)
        # Read and convert SonarQube CWE's into Wiz Import format
        responsejson, issues = convert(sonarqube["sonarqube_url"], sonarqube["auth_key"], key, wiz["integrationId"])
        writejsonfile(responsejson, key)
    
        # Get an upload URL from Wiz
        if issues == "true":
            UP_LOAD_URL, SYSTEM_ACTIVITY_ID = geturl(token, wiz["wiz_api_url"], "wiz_upload_"+key+".json")
            print(f'Upload URL - '+ UP_LOAD_URL)
            # print(f'System Activity ID - '+ SYSTEM_ACTIVITY_ID)

            # Upload findings file to Wiz
            uploadfiletos3(UP_LOAD_URL,"wiz_upload_"+key+".json" )

            # Wait for the Upload to complete before checkign for the upload status
            time.sleep(2)

            # Check the upload response
            response = checkActivity (token, SYSTEM_ACTIVITY_ID, wiz["wiz_api_url"])
            print(json.dumps(response, indent=2))
if __name__ == '__main__':
    main()