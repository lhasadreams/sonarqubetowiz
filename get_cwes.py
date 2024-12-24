import requests
import json
from datetime import datetime, timezone
import argparse
import os

# Read the config.json file
def getconfig (config_file):
    with open(config_file, "r") as file:
        config = json.load(file)
    return config["sonarqube"]["sonarqube_url"], config["sonarqube"]["auth_key"], config["sonarqube"]["project_key"], config["wiz"]["integrationId"]

# Convert the SonarQube input into a file to uplaod to Wiz
def convert(sonarqube_url, auth_key, project_key, integrationId):
    auth = (auth_key, "")

    # Fetch Issues with CWE References
    issues_url = f"{sonarqube_url}/api/issues/search"
    rules_url = f"{sonarqube_url}/api/rules/show"

    params = {
        "componentKeys": project_key,
        "types": "VULNERABILITY",  # Look for vulnerabilities
        "ps": 100,  # Page size
        "p": 1      # Page number
    }

    # Get all the issues from SonarQube - does not take into account any pagination required.
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
                # severity = rule_details["severity"]
                severity = convert_severity(rule_details["severity"])
                # severity = "Critical" # Override as anything does not seem to work
                detailedName = rule_details["name"]
                externalFindingLink = "TBD"
                source = "SonarQube"
                remediation = issue["message"]
                sastfinding = {"sastFinding":{"commitHash":commitHash,"filename":"/"+filename,"lineNumbers":linenumbers},"id": id ,"name": name,"detailedName": detailedName,"severity": severity,"externalFindingLink": externalFindingLink,"source": source,"remediation": remediation}
                responsejson["dataSources"][0]["assets"][0]["webAppVulnerabilityFindings"].append(sastfinding)
            else:
                print(f"Failed to fetch rule details for {rule_key}")
    else:
        print(f"Error: {sonarquberesponse.status_code} - {sonarquberesponse.text}")
    
    return responsejson

# Write the wiz.json file to disk
def writejsonfile(responsejson, config_file):
    filename = "wiz_upload_"+config_file
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

def main():
    # Read the arguments
    config_file = getargs()
    # Check that the file exists
    if not os.path.isfile(config_file):
        print(f"Error: The file '{config_file}' does not exist.")
        exit(1)
    # Read the config file
    sonarqube_url, auth_key, project_key, integrationId = getconfig (config_file)
    # Read and convert SonarQube CWE's into Wiz Import format
    responsejson = convert(sonarqube_url, auth_key, project_key, integrationId)
    writejsonfile(responsejson, config_file)
    
if __name__ == '__main__':
    main()