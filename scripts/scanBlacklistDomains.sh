#!/bin/bash -v
set -e

export GOPATH="/home/zzma/src/golang"

DATE=`date -u +%Y-%m-%d`
DATETIME=`date -u +%Y-%m-%dT%H:%M:%S`
EXEC_PATH="$GOPATH/src/github.com/teamnsrg/safebrowsing/cmd/sblookup"
API_KEY_FILE="$GOPATH/src/github.com/teamnsrg/safebrowsing/.api/sb-api.key"
DOWNLOAD_PATH="/data1/nsrg/domain_blacklists/safebrowsing"
HOSTNAMES_FILE="hostnames.txt"
RESULTS_FILE="results.txt"
LOG_PATH="/data1/nsrg/domain_blacklists/safebrowsing/logs"


# Export hostnames from redis
redis-cli --raw smembers hostnames > $DOWNLOAD_PATH/$DATETIME-$HOSTNAMES_FILE

exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "Something bad happened" | mail -s "REDIS export failed" zanema2@illinois.edu
fi

cd $EXEC_PATH
go build
$EXEC_PATH/sblookup -apikey $(cat $API_KEY_FILE) -server http://localhost:8080 -input $DOWNLOAD_PATH/$DATETIME-$HOSTNAMES_FILE -output $DOWNLOAD_PATH/$DATETIME-$RESULTS_FILE > $LOG_PATH/$DATETIME.log 2>&1

if [ "$1" != 0 ]; then
    cat $LOG_PATH/$DATETIME.log | mail -s "Safebrowsing Script Failed" zanema2@illinois.edu
fi