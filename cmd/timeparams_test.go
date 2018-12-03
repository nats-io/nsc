/*
 * Copyright 2018 The NATS Authors
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

package cmd

import (
	"testing"
	"time"
)

func TestParseExpiry(t *testing.T) {
	type testd struct {
		input   string
		output  int64
		isError bool
	}
	tests := []testd{
		{"", 0, false},
		{"0", 0, false},
		{"19-1-6", 0, true},
		{"2019-1-6", 0, true},
		{"2019-01-6", 0, true},
		{"2019-01-06", time.Date(2019, 1, 6, 0, 0, 0, 0, time.UTC).Unix(), false},
		{"1m", time.Now().Unix() + 60, false},
		{"32m", time.Now().Unix() + 60*32, false},
		{"1h", time.Now().Unix() + 60*60, false},
		{"3h", time.Now().Unix() + 60*60*3, false},
		{"1d", time.Now().AddDate(0, 0, 1).Unix(), false},
		{"3d", time.Now().AddDate(0, 0, 3).Unix(), false},
		{"1w", time.Now().AddDate(0, 0, 7).Unix(), false},
		{"3w", time.Now().AddDate(0, 0, 7*3).Unix(), false},
		{"2M", time.Now().AddDate(0, 2, 0).Unix(), false},
		{"2y", time.Now().AddDate(2, 0, 0).Unix(), false},
	}
	for _, d := range tests {
		v, err := ParseExpiry(d.input)
		if err != nil && !d.isError {
			t.Errorf("%s didn't expect error: %v", d.input, err)
			continue
		}
		if err == nil && d.isError {
			t.Errorf("expected error from %s", d.input)
			continue
		}
		if v != d.output {
			t.Errorf("%s expected %d but got %d", d.input, d.output, v)
		}
	}
}
