// Copyright 2020 The NATS Authors
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

package cmd

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJsonPath_String(t *testing.T) {
	d, err := json.Marshal("helloworld")
	require.NoError(t, err)
	_, err = GetField(d, "hello")
	require.Error(t, err)
}

func TestJsonPath_Int(t *testing.T) {
	d, err := json.Marshal(100)
	require.NoError(t, err)
	_, err = GetField(d, "hello")
	require.Error(t, err)
}

func TestJsonPath_Bool(t *testing.T) {
	d, err := json.Marshal(true)
	require.NoError(t, err)
	_, err = GetField(d, "hello")
	require.Error(t, err)
}

func TestJsonPath_Nil(t *testing.T) {
	d, err := json.Marshal(nil)
	require.NoError(t, err)
	v, err := GetField(d, "hello")
	require.NoError(t, err)
	require.Equal(t, "null", string(v))
}

func TestJsonPath_BadArrayExpression(t *testing.T) {
	d := []byte(`{"a": [0,1,2]}`)
	_, err := GetField(d, "a[1")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unterminated index expression")
}

func TestJsonPath_BadArrayIndex(t *testing.T) {
	d := []byte(`{"a": [0,1,2]}`)
	_, err := GetField(d, "a[]")
	require.Error(t, err)
	require.Contains(t, err.Error(), "error parsing index")
}

func TestJsonPath_BadArrayBadIndex(t *testing.T) {
	d := []byte(`{"a": [0,1,2]}`)
	_, err := GetField(d, "a[ab]")
	require.Error(t, err)
	require.Contains(t, err.Error(), "error parsing index")
}

func TestJsonPath_OutOfBoundsIndex(t *testing.T) {
	d := []byte(`{"a": [0,1,2]}`)
	_, err := GetField(d, "a[4]")
	require.Error(t, err)
	require.Contains(t, err.Error(), "index is out of bounds")
}

func TestJsonPath_PrimitiveCannotBeInspected(t *testing.T) {
	d := []byte(`{"a": [0,1,2]}`)
	_, err := GetField(d, "a[1].hello")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unable to extract")
}

func TestSimple(t *testing.T) {
	d := `{"a":[1,"hello",true],"b": "hello","c": {"key": "one","value": "two"}}`
	ba := []byte(d)
	v, err := GetField(ba, "a")
	require.NoError(t, err)
	require.Equal(t, `[1,"hello",true]`, string(v))

	v, err = GetField(ba, "a[1]")
	require.NoError(t, err)
	require.Equal(t, `"hello"`, string(v))

	v, err = GetField(ba, "a[0]")
	require.NoError(t, err)
	require.Equal(t, "1", string(v))

	v, err = GetField(ba, "a[2]")
	require.NoError(t, err)
	require.Equal(t, "true", string(v))

	v, err = GetField(ba, "b")
	require.NoError(t, err)
	require.Equal(t, `"hello"`, string(v))

	v, err = GetField(ba, "c")
	require.NoError(t, err)
	require.Equal(t, `{"key":"one","value":"two"}`, string(v))

	v, err = GetField(ba, "c.key")
	require.NoError(t, err)
	require.Equal(t, `"one"`, string(v))
}
