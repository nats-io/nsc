/*
 * Copyright 2018-2019 The NATS Authors
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cli

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEmailValidator(t *testing.T) {
	var tests = []struct {
		value      string
		shouldFail bool
	}{
		{"", false},
		{"a", true},
		{"@a", true},
		{"a@a", false}, // this is a bad, but valid email on a local network
		{"a@a.com", false},
	}
	fun := EmailValidator()

	for _, vv := range tests {
		err := fun(vv.value)
		if err != nil && vv.shouldFail == false {
			t.Fatalf("expected not fail: %v", vv.value)
		} else if err == nil && vv.shouldFail {
			t.Fatalf("expected to fail on %v but didn't", vv.value)
		}
	}
}

func TestLengthValidator(t *testing.T) {
	fun := LengthValidator(0)
	require.NoError(t, fun(""))
	require.NoError(t, fun("a"))
	require.NoError(t, fun("aaa"))

	fun = LengthValidator(1)
	require.Error(t, fun(""))
	require.NoError(t, fun("a"))
	require.NoError(t, fun("aaa"))
}
