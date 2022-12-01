// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	istiometadata "istio.io/ztunnel/go-metadata"
)

func main() {
	switch os.Args[1] {
	case "client":
		ip := os.Args[2]
		conn, err := net.Dial("tcp", ip+":9090")
		fatal(err)

		req, err := http.NewRequest("GET", "/", nil)
		fatal(err)
		fatal(req.Write(conn))

		resp, err := http.ReadResponse(bufio.NewReader(conn), req)
		fatal(err)

		rb, err := io.ReadAll(resp.Body)
		fatal(err)

		si, err := istiometadata.FetchFromClientConnection(conn)
		fatal(err)
		log.Println("Connected to server with identity: ", si)
		log.Println("Server response: ", string(rb))
	case "server":
		l, _ := net.Listen("tcp", "0.0.0.0:9090")
		log.Println("listening")
		handler := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			resp := fmt.Sprintf("Got request from %v", istiometadata.ExtractFromRequest(r).Identity)
			rw.Write([]byte(resp))
		})
		fatal(http.Serve(l, istiometadata.Handler(handler)))
	default:
		panic("unknown mode")
	}
}

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}
