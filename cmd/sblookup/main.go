// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Command sblookup is a tool for looking up URLs via the command-line.
//
// The tool reads one URL per line from STDIN and checks every URL against
// the Safe Browsing API. The "Safe" or "Unsafe" verdict is printed to STDOUT.
// If an error occurred, debug information may be printed to STDERR.
//
// To build the tool:
//	$ go get github.com/teamnsrg/safebrowsing/cmd/sblookup
//
// Example usage:
//	$ sblookup -apikey $APIKEY
//	https://google.com
//	Safe URL: https://google.com
//	http://bad1url.org
//	Unsafe URL: [{bad1url.org {MALWARE ANY_PLATFORM URL}}]
package main

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	pb "github.com/teamnsrg/safebrowsing/internal/safebrowsing_proto"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/teamnsrg/safebrowsing"
)

var (
	serverURLFlag      = flag.String("server", safebrowsing.DefaultServerURL, "Safebrowsing API server address.")
	outputFilenameFlag = flag.String("output", "sbresults.txt", "Output file for safebrowsing results.")
	inputFilenameFlag  = flag.String("input", "-", "Input file of urls to check against safebrowsing.")
)

const usage = `sblookup: command-line tool to lookup URLs with Safe Browsing.

Tool reads one URL per line from STDIN and checks every URL against the
Safe Browsing API. The Safe or Unsafe verdict is printed to STDOUT. If an error
occurred, debug information may be printed to STDERR.

Usage: %s -apikey=$APIKEY
`

const (
	codeSafe = (1 << iota) / 2 // Sequence of 0, 1, 2, 4, 8, etc...
	codeUnsafe
	codeFailed
	codeInvalid
)

const (
	threatMatchesPath = "/v4/threatMatches:find"
	LookupBatchSize   = 20000
)

var log *zap.SugaredLogger

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	atom := zap.NewAtomicLevelAt(zap.InfoLevel)
	logger := zap.New(zapcore.NewCore(
		zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()),
		zapcore.Lock(os.Stdout),
		atom), zap.AddCaller(), zap.AddStacktrace(zap.ErrorLevel))
	defer logger.Sync()
	log = logger.Sugar()

	var scanner *bufio.Scanner
	if *inputFilenameFlag == "-" {
		scanner = bufio.NewScanner(os.Stdin)
	} else {
		inputFile, _ := os.Open(*inputFilenameFlag)
		defer inputFile.Close()
		scanner = bufio.NewScanner(inputFile)
	}

	threats := make([]*pb.ThreatEntry, 0)
	threatMatches := make(chan *pb.FindThreatMatchesResponse, LookupBatchSize)
	var wg sync.WaitGroup
	go writeOutput(threatMatches, *outputFilenameFlag, &wg)

	validURLCount := 0
	previousLineCount, lineCount := 1, 0
	for scanner.Scan() {
		lineCount += 1
		inputUrl := scanner.Text()
		_, err := safebrowsing.ParseURL(inputUrl)
		if err != nil {
			log.Warn(err, inputUrl)
			continue
		}

		threats = append(threats, &pb.ThreatEntry{Url: inputUrl})
		validURLCount += 1
		if validURLCount%LookupBatchSize == 0 {
			log.Infof("sending lookup request for lines %d to %d", previousLineCount, lineCount)
			threats = make([]*pb.ThreatEntry, 0)
			previousLineCount = lineCount
		}
	}

	if len(threats) > 0 {
		log.Infof("sending lookup request for lines %d to %d", previousLineCount, lineCount)
	}

	if scanner.Err() != nil {
		log.Error("input read error:", scanner.Err())
	} else {
		log.Info("finished reading input from stdin")
	}

	wg.Wait()
	close(threatMatches)
}

func writeOutput(responses chan *pb.FindThreatMatchesResponse, outputFilename string, wg *sync.WaitGroup) {
	// open output file
	outFile, err := os.Create(outputFilename)
	if err != nil {
		log.Error(outFile)
	}
	defer outFile.Close()

	w := csv.NewWriter(outFile)

	for response := range responses {
		for _, match := range response.Matches {
			if err := w.Write(match.StringSlice()); err != nil {
				log.Error("csv writing error:", err)
			}
		}
		log.Info("results written to csv")
		w.Flush()
		wg.Done()
	}
}

func checkFullHashes(serverURL string, entries []*pb.ThreatEntry, matches chan *pb.FindThreatMatchesResponse, wg *sync.WaitGroup) {
	reqData := &pb.FindFullHashesRequest{
		Client: &pb.ClientInfo{
			ClientId:      "NSRG",
			ClientVersion: "1.0",
		},
		ThreatInfo: &pb.ThreatInfo{
			PlatformTypes:    []pb.PlatformType{pb.PlatformType_PLATFORM_TYPE_UNSPECIFIED},
			ThreatTypes:      []pb.ThreatType{pb.ThreatType_THREAT_TYPE_UNSPECIFIED},
			ThreatEntryTypes: []pb.ThreatEntryType{pb.ThreatEntryType_THREAT_ENTRY_TYPE_UNSPECIFIED},
			ThreatEntries:    entries,
		},
	}

	u, err := url.Parse(serverURL)
	if err != nil {
		log.Error("invalid server URL: ", err)
	}
	u.Path = threatMatchesPath

	reqJsonBytes, err := json.Marshal(reqData)
	if err != nil {
		log.Error("invalid threat info struct: ", err)
	}

	httpReq, err := http.NewRequest("POST", u.String(), bytes.NewReader(reqJsonBytes))
	httpReq.Header.Add("Content-Type", "application/json")
	client := &http.Client{}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		log.Error("http error: ", err)
	} else {
		log.Info("response received")
	}
	defer httpResp.Body.Close()

	body, _ := ioutil.ReadAll(httpResp.Body)

	log.Debug("response body: ", string(body))

	resp := new(pb.FindThreatMatchesResponse)
	if err := json.Unmarshal(body, resp); err != nil {
		log.Error(err)
	}

	wg.Add(1)
	matches <- resp
}
