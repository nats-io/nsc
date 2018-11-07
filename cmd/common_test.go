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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseDate(t *testing.T) {
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

func TestParseNumber(t *testing.T) {
	type testd struct {
		input   string
		output  int64
		isError bool
	}
	tests := []testd{
		{"", 0, false},
		{"0", 0, false},
		{"1000", 1000, false},
		{"1K", 1000, false},
		{"1k", 1000, false},
		{"1M", 1000000, false},
		{"1m", 1000000, false},
		{"1G", 1000000000, false},
		{"1g", 1000000000, false},
		{"32a", 0, true},
	}
	for _, d := range tests {
		v, err := ParseNumber(d.input)
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

func TestOkToWrite(t *testing.T) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal("error creating tmpdir", err)
	}

	type testd struct {
		fp           string
		expected     bool
		shouldCreate bool
		isDir        bool
	}
	tests := []testd{
		{"--", true, false, false},
		{filepath.Join(dir, "dir"), false, true, true},
		{filepath.Join(dir, "nonExisting"), true, false, false},
		{filepath.Join(dir, "existing"), false, true, false},
	}
	for _, d := range tests {
		if d.shouldCreate && !d.isDir {
			os.Create(d.fp)
		}
		if d.shouldCreate && d.isDir {
			os.MkdirAll(d.fp, 0777)
		}

		if ok := OkToWrite(d.fp); ok != d.expected {
			t.Errorf("didn't expect to be able to write %q", d.fp)
			continue
		}
	}
}

func TestGetOutput(t *testing.T) {
	dir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatal("error creating tmpdir", err)
	}

	type testd struct {
		fp      string
		create  bool
		isError bool
		isDir   bool
	}
	tests := []testd{
		{"--", false, false, false},
		{filepath.Join(dir, "dir"), true, true, true},
		{filepath.Join(dir, "nonExisting"), false, false, false},
		{filepath.Join(dir, "existing"), false, false, false},
	}
	for _, d := range tests {
		if d.isDir {
			os.MkdirAll(d.fp, 0777)
		} else if d.create {
			os.Create(d.fp)
		}
		file, err := GetOutput(d.fp)
		if file != nil && d.fp != "--" {
			file.Close()
		}
		if d.isError && err == nil {
			t.Errorf("expected error creating %q, but didn't", d.fp)
		}
		if !d.isError && err != nil {
			t.Errorf("unexpected error creating %q: %v", d.fp, err)
		}
	}
}

func StripTableDecorations(s string) string {
	decorations := []string{"╭", "─", "┬", "╮", "├", "│", "┤", "╰", "┴", "╯"}
	for _, c := range decorations {
		s = strings.Replace(s, c, "", -1)
	}
	return s
}
