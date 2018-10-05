import requests
import json
import csv

url = "127.0.0.1:8080/v4/threatMatches:find"

x = {
	'threatInfo': {
	'threatTypes': ['ANY_TYPE'], #TODO check this
		'threadEntries': []
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

x['threatInfo']['threadEntries'] = entries
request = requests.post(url, params=x)
print request.txt
#print (json.dumps(x))