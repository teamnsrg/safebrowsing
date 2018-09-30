import requests
import json
import csv

url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="

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

with open('blacklist-entries.csv') as csvfile:
    spamreader = csv.reader(csvfile, delimiter=',')
    next(spamreader)
    for row in spamreader:
		if(row[0][:2] == '//'):
			newEntry = 	{'url':row[0][2:]}
			
		else:
			newEntry = 	{'url':row[0]}

		#print(newEntry)	
		entries.append(newEntry)
#print(entries)

x['threatInfo']['threadEntries'] = entries
print (json.dumps(x))