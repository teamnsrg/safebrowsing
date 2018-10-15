#Usage python parse-csv.py api-key inputCSV outputCSV

from functools import wraps

try:
	import urllib, urlparse
except ImportError:
	import urllib.parse as urllib
	from urllib import parse as urlparse

import struct
import time
import posixpath
import re
import hashlib
import socket
import random
import base64
import requests
import json
import csv
import datetime
import sys

urlLookup = dict()
partialHashLookup = dict()

def full_unescape(u):
	uu = urllib.unquote(u)
	if uu == u:
		return uu
	else:
		return full_unescape(uu)

def quote(s):
	safe_chars = '!"$&\'()*+,-./:;<=>?@[\\]^_`{|}~'
	return urllib.quote(s, safe=safe_chars)

def canonical(s):
	url = s.strip()
	url = url.replace('\n', '').replace('\r', '').replace('\t', '')
	url = url.split('#', 1)[0]
	if url.startswith('//'):
		 url = 'http:' + url
	if len(url.split('://')) <= 1:
		url = 'http://' + url
	url = quote(full_unescape(url))
	url_parts = urlparse.urlsplit(url)
	if not url_parts[0]:
		url = 'http://%s' % url
		url_parts = urlparse.urlsplit(url)
	protocol = url_parts.scheme
	host = full_unescape(url_parts.hostname)
	path = full_unescape(url_parts.path)
	query = url_parts.query
	if not query and '?' not in url:
		query = None
	if not path:
		path = '/'
	has_trailing_slash = (path[-1] == '/')
	path = posixpath.normpath(path).replace('//', '/')
	if has_trailing_slash and path[-1] != '/':
		path = path + '/'
	port = url_parts.port
	host = host.strip('.')
	host = re.sub(r'\.+', '.', host).lower()
	if host.isdigit():
		try:
			host = socket.inet_ntoa(struct.pack("!I", int(host)))
		except:
			pass
	if host.startswith('0x') and '.' not in host:
		try:
			host = socket.inet_ntoa(struct.pack("!I", int(host, 16)))
		except:
			pass
	quoted_path = quote(path)
	quoted_host = quote(host)
	if port is not None:
		quoted_host = '%s:%s' % (quoted_host, port)
	canonical_url = '%s://%s%s' % (protocol, quoted_host, quoted_path)
	if query is not None:
		canonical_url = '%s?%s' % (canonical_url, query)
	#print("canonical url is " + canonical_url)
	return canonical_url

def url_host_permutations(host):
	if re.match(r'\d+\.\d+\.\d+\.\d+', host):
		yield host
		return
	parts = host.split('.')
	l = min(len(parts),5)
	if l > 4:
		yield host
	for i in range(l-1):
		yield '.'.join(parts[i-l:])

def url_path_permutations(path):
	yield path
	query = None
	if '?' in path:
		path, query =  path.split('?', 1)
	if query is not None:
		yield path
	path_parts = path.split('/')[0:-1]
	curr_path = ''
	for i in range(min(4, len(path_parts) )):
		curr_path = curr_path + path_parts[i] + '/'
		yield curr_path

def url_permutations(url):
#	print("in url_permutations, url is " + url)
	protocol, address_str = urllib.splittype(url)
	host, path = urllib.splithost(address_str)
	user, host = urllib.splituser(str(host))
	host, port = urllib.splitport(host)
	host = host.strip('/')
	seen_permutations = set()
	for h in url_host_permutations(host):
		for p in url_path_permutations(path):
			u = '%s%s' % (h, p)
			if u not in seen_permutations:
				yield u

				seen_permutations.add(u)

def digest(url):
	digest = hashlib.sha256(url.encode('utf-8')).digest()
	urlLookup[base64.b64encode(digest)] = url
	return digest

def hashes(url):
	url_hash = digest(url)
	yield url_hash


if __name__ == '__main__':
	url = "https://safebrowsing.googleapis.com/v4/fullHashes:find?key=" + sys.argv[1]

	x = {
			'client':{
			'clientId': 'NSRG',
			'clientVersion': '1.0'
			},
			'clientStates':[],
			'threatInfo': {
			'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION', 'THREAT_TYPE_UNSPECIFIED'],
			'platformTypes': ['ANY_PLATFORM'],
			'threatEntryTypes':['URL'],
			'threatEntries': []
			},
			'apiClient':{},
	}

	entries = [	]


	i = 0;
	send = 0
	with open(sys.argv[2]) as csvfile:
		with open(sys.argv[3], "w+") as outfile:
			blacklistWriter = csv.writer(outfile, delimiter=',')
			blacklistReader = csv.reader(csvfile, delimiter=',')
			blacklistWriter.writerow(['URL', 'Full Hash', 'Partial Hash', 'UTC Time Stamp', 'Match Type', 'Match Metadata', 'Platform'])
			next(blacklistReader)
			for row in blacklistReader:
				if (i % 200 == 0):
					send = 1
				if(row[0][:2] == '//'):
					inputURL = row[0][2:]
				else:
					inputURL = row[0]
				for permutations in url_permutations(canonical(inputURL)):
					for hashed in hashes(permutations):
						hashValue = base64.b64encode(hashed[0:4])
						partialHashLookup[base64.b64encode(hashed)] = hashValue
						hashValue.replace('\n', '')
						newEntry = {'hash': hashValue}
						entries.append(newEntry)
				i = i + 1;

				if send == 1:
					x['threatInfo']['threatEntries'] = entries
					response = requests.post(url, json=x)
					responseJSON = json.loads(response.text)
					if 'matches' in responseJSON:
						for hits in responseJSON['matches']:
							if 'threatType' in hits:
								threatType = hits['threatType']
							if 'platformType' in hits:
								platformType = hits['platformType']
							currentHash = ''
							if 'threat' in hits:
								currentHash = hits['threat']['hash']
							malwareType = ''
							timestamp = datetime.datetime.utcnow()
							if 'threatEntryMetadata' in hits:
								if 'entries' in hits['threatEntryMetadata']:
									malwareTypeHash = hits['threatEntryMetadata']['entries'][0]['value']
									if 'TEFORElORw' in malwareTypeHash:
										malwareType = 'MALWARE LANDING'
									if 'RElTVFJJQlVUSU9O' in malwareTypeHash:
										malwareType = 'MALWARE DISTRIBUTION'

							if currentHash in urlLookup:
								currentURL = urlLookup[currentHash]
								urlLookup.pop(currentHash)
							else:
								currentURL = ""

							if currentHash in partialHashLookup:
								partialHash = partialHashLookup[currentHash]
								partialHashLookup.pop(currentHash)
							else:
								partialHash = ""
							blacklistWriter.writerow([currentURL, currentHash, partialHash, timestamp, threatType, malwareType, platformType])
					send = 0
					entries = []
			leftovers = urlLookup.items()
			for extra in leftovers:
				blacklistWriter.writerow([extra[1], extra[0], partialHashLookup[extra[0]], timestamp, "", "", ""])






