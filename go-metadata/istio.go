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

package istiometadata

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

// ConnectionMetadata returns the metadata about a connection
type ConnectionMetadata struct {
	// Identity provides the identity of the peer.
	// Example: spiffe://cluster.local/ns/a/sa/b.
	Identity string `json:"identity"`
}

// metadataClient provides a default client for all metadata requests
var metadataClient = http.Client{
	Timeout: time.Second,
}

// metadataContextKey is the key the metadata handler will store connection metadata in
var metadataContextKey = &contextKey{}

type contextKey struct {
	name string
}

func (k *contextKey) String() string { return "istio metadata context value" }

const mdsHostEnv = "GCE_METADATA_HOST"

// For now, we use a well-known IP which is intercepted.
// TODO: consider creating a real service with node-affinity to drop redirection dependency.
const defaultHost = "169.254.169.111"

func metadataServerURL() *url.URL {
	host := os.Getenv(mdsHostEnv)
	if host == "" {
		host = defaultHost
	}
	u, err := url.Parse("http://" + host)
	if err != nil {
		panic(err.Error())
	}
	return u
}

func lookup(src, dst string) (*ConnectionMetadata, error) {
	u := metadataServerURL()
	params := url.Values{}
	params.Add("src", src)
	params.Add("dst", dst)
	u.RawQuery = params.Encode()
	u.Path = "/connection"

	resp, err := metadataClient.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("metadata lookup failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		bdy, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("metadata server returned %v: %v", resp.StatusCode, string(bdy))
	}

	mr := &ConnectionMetadata{}
	if err := json.NewDecoder(resp.Body).Decode(mr); err != nil {
		return nil, err
	}
	return mr, nil
}

// Handler is an HTTP middleware that looks up the metadata for each request, storing it in context.
// It can later be looked up with ExtractFromRequest.
func Handler(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Context().Value(metadataContextKey) != nil {
			h.ServeHTTP(w, r)
			return
		}
		local := r.Context().Value(http.LocalAddrContextKey)
		cm, err := lookup(r.RemoteAddr, local.(*net.TCPAddr).String())
		if err != nil {
			// Nothing we can do
			h.ServeHTTP(w, r)
			return
		}
		// Serve underlying handler
		ctx := context.WithValue(r.Context(), metadataContextKey, cm)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ExtractFromRequest attempts to extract ConnectionMetadata from a request.
// This requires Handler to be used.
// If a connection is re-used between requests, only a single call will be made.
func ExtractFromRequest(r *http.Request) *ConnectionMetadata {
	v := r.Context().Value(metadataContextKey)
	if v == nil {
		return nil
	}
	return v.(*ConnectionMetadata)
}

// FetchFromRequest attempts to fetch ConnectionMetadata from a request.
// This will make a call for each request, which may be inefficient.
func FetchFromRequest(r *http.Request) (*ConnectionMetadata, error) {
	local := r.Context().Value(http.LocalAddrContextKey)
	return lookup(r.RemoteAddr, local.(*net.TCPAddr).String())
}

// FetchFromClientConnection attempts to fetch ConnectionMetadata from a client connection.
func FetchFromClientConnection(c net.Conn) (*ConnectionMetadata, error) {
	return lookup(c.LocalAddr().String(), c.RemoteAddr().String())
}

// FetchFromServerConnection attempts to fetch ConnectionMetadata from a server connection.
func FetchFromServerConnection(c net.Conn) (*ConnectionMetadata, error) {
	return lookup(c.RemoteAddr().String(), c.LocalAddr().String())
}
