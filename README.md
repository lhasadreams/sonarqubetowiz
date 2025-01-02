# sonarqubetowiz

Usage:
Create a ``config.json`` file from ``config.json.example``

See the [WIN Integration docs](https://win.wiz.io/docs/introduction) for the Wiz Parameters

```{
    "wiz": {
        "client_id": "",
        "client_secret": "",
        "wiz_url": "",
        "wiz_api_url": "",
        "integrationId": ""

    },
    "sonarqube": {
        "sonarqube_url": "http://sonarcloud.io",
        "auth_key": "",
        "organization": "your_sonarqube_organization"
    }
}
```

To get all the CWE's in your SonarQube Organisations Projects and add them in to Wiz

``python3 sqtowiz.py -c config.json``

Typical Output:

```
lhasadreams_vulnerable-code-examples
Found 35 vulnerabilities.
Upload URL - https://file-upload...
Upload file succeeded

{
  "data": {
    "systemActivity": {
      "id": "xxxxxxxxxxxxxxxxxxxx",
      "status": "SUCCESS",
      "statusInfo": null,
      "result": {
        "dataSources": {
          "incoming": 1,
          "handled": 1
        },
        "findings": {
          "incoming": 35,
          "handled": 35
        },
        "events": {
          "incoming": 0,
          "handled": 0
        },
        "tags": {
          "incoming": 0,
          "handled": 0
        }
      },
      "context": {
        "fileUploadId": "706094"
      }
    }
  }
}
```