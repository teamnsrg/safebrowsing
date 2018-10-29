#!/bin/bash -v
set -e

export GOPATH="/home/zzma/src/golang"

DATE=`date -u +%Y-%m-%d`
DATETIME=`date -u +%Y-%m-%dT%H:%M:%S`
EXEC_PATH="$GOPATH/src/github.com/teamnsrg/safebrowsing/cmd/sblookup"
DOWNLOAD_PATH="/data1/nsrg/domain_blacklists/safebrowsing"
URLS_FILE="urls.txt"
RESULTS_FILE="results.txt"
LOG_PATH="/data1/nsrg/domain_blacklists/safebrowsing/logs"


# Export hostnames from redis
redis-cli --raw smembers urls > $DOWNLOAD_PATH/$DATETIME-$URLS_FILE

exit_status=$?
if [ $exit_status -ne 0 ]; then
    echo "Something bad happened" | mail -s "REDIS export failed" zanema2@illinois.edu
fi

cd $EXEC_PATH
go build
$EXEC_PATH/sblookup -server http://localhost:8080 -input $DOWNLOAD_PATH/$DATETIME-$URLS_FILE -output $DOWNLOAD_PATH/$DATETIME-$RESULTS_FILE > $LOG_PATH/$DATETIME.log 2>&1
