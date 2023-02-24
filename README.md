## Basic Cyber Vision Dashboard Tile Example
To be used with the integration tile available here:
https://github.com/ste-matt/secureX-CV-tile-V1

This is a demonstration integration which can be used with a real instance of Cyber Vision.
You need to download and add the test tile using the module builder on github into your 
secureX environment link for module maker:
https://ciscosecurity.github.io/tr-05-module-maker/

As of creation (Jan  23) there is no independent Cyber Vision license, so you need to have an existing  licensed integration for another platform to use this tile within your environment.

*There are 5 dashboard elements included they have basic functionality, some reflect the actual Cyber Vision dashboard GUI elements*

1. List of Vulnerabilities ordered by severity for all assets - the CVE hotlinks work
2. Top 20  List of High and Very High Events ordered by most recent
3. Event category values for the last 30 days - limited max count value 2000 across all fields
4. Vulnerable device counts (no drill down available) - Donut tile same data as the security login dashboard equivalent
5. Devices by risk score (no drill down available) - Donut tile same data as the security login dashboard equivalent 

There are a couple of hidden/commented out tiles.. one is risk in a bar chart format - the other is a simple test markdown tile.

This was tested/deployed locally and also as an Azure Web App - it has not been tested or built for AWS

Brief information on Files:

 **app.py**:
*Contains  the flask module, it recieves the API calls from the integration module and processes locally for the tiles and tile formats,
it decodes the JWT contents and extracts the Cyber Vision IP or domain and API token and onward forwards the request using the methods for each tile type*

**tile_formats.py**:
*Contains the actual tile formats displayed on the dashboard*

**tile_data_formats.py**:
*Formats the actual dynamic data for each tile based on the API call response processing*

**schema.py**:
*Validates the request for which tile data is required when the Integration module requests an update*

**icons_for_metric_group.txt**:
*Provides the small icons used by the metric's*

**requirements.txt**:
*Used for deployment and required by Azure when installing a web app to provide module data*

**error.py & templates/error.html **
THERE IS LIMITED ERROR HANDLING IN THIS APP & THIS FILE & TEMPLATE ARE NOT BEING USED AT THIS TIME
CURRENTLY THE ONWARD API CALL HAS A TIMEOUT ACTIVE, WHICH IS 5 SECONDS, IF THE TIMEOUT IS HIT , DEBUG WILL PRINT AN ERROR MESSAGE TO SHOW NO RESPONSE FROM THE REMOTE SYSTEM.

**Less important**:

**CV-dashboard-data-accurate.json**
Just provides a typical view of returned Cyber Vision API data..

**demo.json**
Provides an example of Cyber Vision API response for a vulnerability.


**THIS IS DEMO CODE - NO WARRANTY OR SUPPORT IS IMPLIED OR PROVIDED**

Tested with Cyber Vision 4.1.x


 Some todo list items :
1.Rework the event list dashboard - its using markdown , but could use the table as per vulnerabilities

2.JWT and JWKS handling - the KID validation of the inbound JWT needs work - as if this version I was unable to get Cisco JWKS KID to validate the payload.
I do a basic decode of the hash and extract the Cyber Vision IP and token

3.Add some time based variation to dashboard

4. Some loops need updating to use enumerate

5. Hotlinks from dashboard elements could be added

*Steve Matthews stmatthe@cisco.com - Feb 23*
