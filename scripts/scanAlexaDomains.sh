#!/bin/bash -v
set -e

export GOPATH="/home/zzma/src/golang"

DATE=`date -u +%Y-%m-%d`
DATETIME=`date -u +%Y-%m-%dT%H:%M:%S`
EXEC_PATH="$GOPATH/src/github.com/teamnsrg/safebrowsing/cmd/sblookup"
DOWNLOAD_PATH="/data1/nsrg/domain_blacklists/safebrowsing_alexa"
URLS_FILE="urls.txt"
RESULTS_FILE="results.txt"
LOG_PATH="/data1/nsrg/domain_blacklists/safebrowsing_alexa/logs"
TOP_DOMAINS_FILE="$GOPATH/src/github.com/teamnsrg/safebrowsing/filters/top-1m.txt"

mkdir -p $DOWNLOAD_PATH/$DATE

cd $EXEC_PATH
go build
$EXEC_PATH/sblookup -server http://localhost:8080 -input $TOP_DOMAINS_FILE -output $DOWNLOAD_PATH/$DATE/$DATETIME-$RESULTS_FILE > $LOG_PATH/$DATETIME.log 2>&1
