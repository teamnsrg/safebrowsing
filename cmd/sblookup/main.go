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
	"encoding/json"
	"flag"
	"fmt"
	pb "github.com/teamnsrg/safebrowsing/internal/safebrowsing_proto"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"

	"github.com/teamnsrg/safebrowsing"
)

var (
	serverURLFlag = flag.String("server", safebrowsing.DefaultServerURL, "Safebrowsing API server address.")
)

const usage = `sblookup: command-line tool to lookup URLs with Safe Browsing.

Tool reads one URL per line from STDIN and checks every URL against the
Safe Browsing API. The Safe or Unsafe verdict is printed to STDOUT. If an error
occurred, debug information may be printed to STDERR.

Exit codes (bitwise OR of following codes):
  0  if and only if all URLs were looked up and are safe.
  1  if at least one URL is not safe.
  2  if at least one URL lookup failed.
  4  if the input was invalid.

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
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, usage, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	scanner := bufio.NewScanner(os.Stdin)
	code := codeSafe
	threats := make([]*pb.ThreatEntry, 0)
	for scanner.Scan() {
		inputUrl := scanner.Text()
		_, err := safebrowsing.ParseURL(inputUrl)
		if err != nil {
			fmt.Fprintln(os.Stdout, err, inputUrl)
		} else {
			threats = append(threats, &pb.ThreatEntry{Url: inputUrl})
		}
	}

	if scanner.Err() != nil {
		fmt.Fprintln(os.Stderr, "Unable to read input:", scanner.Err())
		code |= codeInvalid
	}
	reqData := &pb.FindFullHashesRequest{
		Client: &pb.ClientInfo{
			ClientId:      "NSRG",
			ClientVersion: "1.0",
		},
		ThreatInfo: &pb.ThreatInfo{
			PlatformTypes:    []pb.PlatformType{pb.PlatformType_PLATFORM_TYPE_UNSPECIFIED},
			ThreatTypes:      []pb.ThreatType{pb.ThreatType_THREAT_TYPE_UNSPECIFIED},
			ThreatEntryTypes: []pb.ThreatEntryType{pb.ThreatEntryType_THREAT_ENTRY_TYPE_UNSPECIFIED},
			ThreatEntries:    threats,
		},
	}

	u, err := url.Parse(*serverURLFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid server URL")
	}
	u.Path = threatMatchesPath

	reqJsonBytes, err := json.Marshal(reqData)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Invalid threat info struct")
	}
	httpReq, err := http.NewRequest("POST", u.String(), bytes.NewReader(reqJsonBytes))
	httpReq.Header.Add("Content-Type", "application/json")
	client := &http.Client{}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		fmt.Fprintln(os.Stderr, "HTTP error: %s", err.Error())
	}
	defer httpResp.Body.Close()

	fmt.Println("response Status:", httpResp.Status)
	fmt.Println("response Headers:", httpResp.Header)
	body, _ := ioutil.ReadAll(httpResp.Body)
	fmt.Println("response Body:", string(body))

	os.Exit(code)
}
