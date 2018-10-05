import requests
import json
import csv

url = "https://safebrowsing.googleapis.com/v4/fullHashes:find?key=AIzaSyC4EjprVfp6YX6aSlHqFZhaUrmbgRMoi7w"

x = {

        'client':{
        'clientId': 'IllinoisNSRG',
        'clientVersion': '1.0',
        },
	'threatInfo': {
	'threatTypes': ['THREAT_TYPE_UNSPECIFIED'],
	'platformTypes': ['ANY_PLATFORM'],
	'threatEntryTypes':['URL'],
	'threatEntries': [
      {"hash": "WwuJdQ=="},
      {"hash": "771MOg=="},
      {"hash": "5eOrwQ=="}	]
	},
	'apiClient':{
	'clientId': 'IllinoisNSRG',
	'clientVersion': '1.0',
	}
}

entries = [
	{'url':'google.com'},
]

#print (entries[0]['url'])
i = 0;
with open('blacklist-entries.csv') as csvfile:
	spamreader = csv.reader(csvfile, delimiter=',')
	next(spamreader)
	for row in spamreader:
		if (i == 10):
			break
		if(row[0][:2] == '//'):
			newEntry = 	{'url':row[0][2:]}

		else:
			newEntry = 	{'url':row[0]}

		#print(newEntry)
		entries.append(newEntry)
		i = i + 1;
#print(entries)


#x['threatInfo']['threatEntries'] = entries
#print(x)
response = requests.post(url, json=x)
print (response.text)
#print (response.json())
print (json.dumps(x))
