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
	"testing"

	"github.com/stretchr/testify/require"
)

func TestResolvePath(t *testing.T) {
	v := ResolvePath("bar", "foo")
	require.Equal(t, v, "bar", "non defined variable")

	v = ResolvePath("bar", "")
	require.Equal(t, v, "bar", "empty variable")

	os.Setenv("foo", "foobar")
	v = ResolvePath("bar", "foo")
	require.Equal(t, v, "foobar", "env set")
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

func TestIsStdOut(t *testing.T) {
	require.True(t, IsStdOut("--"))
	require.False(t, IsStdOut("/tmp/foo.txt"))
}

func TestResolveKeyEmpty(t *testing.T) {
	old := KeyPathFlag
	KeyPathFlag = ""

	rkp, err := ResolveKeyFlag()
	KeyPathFlag = old

	require.NoError(t, err)
	require.Nil(t, rkp)
}

func TestResolveKeyFromSeed(t *testing.T) {
	seed, p, _ := CreateAccountKey(t)
	old := KeyPathFlag
	KeyPathFlag = string(seed)

	rkp, err := ResolveKeyFlag()
	KeyPathFlag = old

	require.NoError(t, err)

	pp, err := rkp.PublicKey()
	require.NoError(t, err)

	require.Equal(t, pp, p)
}

func TestResolveKeyFromFile(t *testing.T) {
	dir := MakeTempDir(t)
	_, p, kp := CreateAccountKey(t)
	old := KeyPathFlag
	KeyPathFlag = StoreKey(t, kp, dir)
	rkp, err := ResolveKeyFlag()
	KeyPathFlag = old

	require.NoError(t, err)

	pp, err := rkp.PublicKey()
	require.NoError(t, err)

	require.Equal(t, pp, p)
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
