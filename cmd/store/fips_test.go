// Copyright 2018-2022 The NATS Authors
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

package store

import (
	"testing"

	"github.com/nats-io/nsc/v2/internal/fips"
)

// skipIfFIPS skips the current test under strict FIPS enforcement
// (GODEBUG=fips140=only) with the given reason. Tests covered by this
// helper exercise curve (X25519) operations, which panic under strict
// mode; under the looser fips140=on they continue to run.
func skipIfFIPS(t *testing.T, reason string) {
	t.Helper()
	if fips.Enforced() {
		t.Skip(reason)
	}
}

const skipReasonFIPSCurve = "curve (X25519) operations are disabled under FIPS"
