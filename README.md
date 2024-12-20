# sonarqubetowiz

Usage:
Create a ``config.json`` file from ``config.json.example``

To get the vulnerabilites (with CWE's) from SonarQube and convert them into the Wiz upload format.\
``python get_cwes.py --config config.json``

This will produce a ``wiz_upload_config.json`` file.

To upload the SAST data to Wiz.\
``python upload.py --config config.json --upload wiz_upload_config.json``
