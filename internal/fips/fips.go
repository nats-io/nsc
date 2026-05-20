// Copyright 2026 The NATS Authors
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

// Package fips reports FIPS 140-3 mode and provides helpers to gate operations
// that rely on cryptography not approved by the Go FIPS 140-3 module.
package fips

import (
	"crypto/fips140"
	"fmt"
	"strings"
)

// Enabled reports whether the Go FIPS 140-3 module is active (GODEBUG=fips140=on
// or fips140=only, or built with //go:debug fips140=...).
func Enabled() bool {
	return fips140.Enabled()
}

// DisabledError returns an error indicating an operation is unavailable in the
// FIPS build. op is the user-facing operation name and algo the algorithm or
// primitive that is not part of the FIPS 140-3 module.
func DisabledError(op, algo string) error {
	return fmt.Errorf("%s is disabled in FIPS mode: %s is not part of the FIPS 140-3 approved algorithm set; use a non-FIPS build of nsc to perform this operation", op, algo)
}

// CheckWebSocketURL returns an error when running under FIPS and any of the
// provided URLs use ws:// or wss://.
//
// Background: the nats.go client computes SHA-1 unguarded in its WebSocket
// handshake (Sec-WebSocket-Accept), which panics under GODEBUG=fips140=only.
// nats-server ships an fips140.WithoutEnforcement bypass for the same path
// (https://github.com/nats-io/nats-server/pull/8141, merge 7224db1) but
// nats.go does not yet have an equivalent. Until that lands upstream we
// refuse WebSocket URLs up front so users get a clear error instead of a
// runtime panic. Each argument may contain a comma-separated list of URLs.
func CheckWebSocketURL(urls ...string) error {
	if !Enforced() {
		return nil
	}
	for _, u := range urls {
		for _, p := range strings.Split(u, ",") {
			s := strings.ToLower(strings.TrimSpace(p))
			if strings.HasPrefix(s, "ws://") || strings.HasPrefix(s, "wss://") {
				return fmt.Errorf("WebSocket URLs (ws://, wss://) are not supported in FIPS mode")
			}
		}
	}
	return nil
}
