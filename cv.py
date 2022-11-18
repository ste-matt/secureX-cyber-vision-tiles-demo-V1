
import json
import os

import requests


auth_token = "ics-becf2ba10ba7058ffb9651d69df46e8131090c22-d96b3d752a2899c4c4a0895076e944df49005ccb"
headers = {"Content-Type": "application/json; charset=utf-8", "x-token-id": auth_token}
events = []

# def cv140_ec():
#     response=requests.get('https://172.16.0.140/api/3.0/homepage/dashboard', headers=headers , verify=False)
#     payload=response.content
#     json_payload=json.loads(payload)    
#     values_x = {}
#     values_y = {}
#     values_x =json_payload['event']
#     values_y = values_x['total']

#     for v in values_y.values():
#         events.append(v)

#     total = events[0]
#     low = events[1]
#     medium = events[2]      
#     high = events [3]
#     critical = events[4]
#     #print(total,low,medium,high,critical)
    
      
cv140_ec()
response=requests.get('https://172.16.0.140/api/3.0/homepage/dashboard', headers=headers , verify=False)
    payload=response.content
    json_payload=json.loads(payload)
#     print("Event Counts")
#     print("============")
#     A = (json_payload['centers'][0]['total'])
#     print("Total is " + str(A))
#     print(json_payload['centers'][0]['total'])
    
#     B = (json_payload['centers'][0]['low'])
#     print("Low is " + str(B))
#     C = (json_payload['centers'][0]['medium'])
#     print("Medium is " + str(C))
#     D = (json_payload['centers'][0]['high'])
#     print("High  is " + str(D))
#     E = (json_payload['centers'][0]['critical'])
#     print("Critical  is " + str(E))
   return (json_payload['centers'][0]['total'],json_payload['centers'][0]['low'],json_payload['centers'][0]['medium'],json_payload['centers'][0]['high'],json_payload['centers'][0]['critical'])
   
total,low,medium, high , critical = cv140_ec()

print(total,low,medium,high,critical)



