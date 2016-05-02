# VirusTotal Threat Intelligence Gathering Script

This script is used to sync-up with VirusTotal file/url feeds API and store meta-data of every submission to Virustotal in a MongoDB instance. This information can later be utilized for threat intelligence gathering.

This script is based on Emiliano Martinez example script used to interact with VirusTotal's
feeds APIs. The API is documented at: https://www.virustotal.com/documentation/private-api/

Please contact VirusTotal to obtain a Private API key for this script to function properly.

## Authors

* **Emiliano Martinez** - *Initial script*
* **Lior Ben-Porat** - *Everything else*


### Prerequisities

Please install the following Python packages before running the script

```
ConfigParser
pymongo
requests
```

### How to use

Run this script in a cronjob of 1 minute intervals in order to keep a track of the live submissions on VirusTotal.
```
*/1 * * * * python PATH_TO_SCRIPT/vtfeeds.py file
*/1 * * * * python PATH_TO_SCRIPT/vtfeeds.py url
```
Before using this script use following command in your MongoDB instance in order to index the 'sha256' and 'url' fields for optimized query speeds:
```
db.file.createIndex({sha256:1})
db.url.createIndex({url:1})
```

## License

Do whatever you want with it
