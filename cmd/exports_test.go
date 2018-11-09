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

	"github.com/stretchr/testify/require"
)

func TestEmptyExports(t *testing.T) {
	_, _, _ = CreateTestStore(t)

	var exports Exports
	require.NoError(t, exports.Load(), "error loading")

	require.Zero(t, exports.Len())
}

func TestExports_AddService(t *testing.T) {
	_, _, _ = CreateTestStore(t)

	var exports Exports
	require.NoError(t, exports.Load(), "error loading")
	require.Zero(t, exports.Len())

	exports.Add(NewServiceExport("Super Foo", "foo", "Foo"))
	require.Equal(t, 1, exports.Len())
}

func TestExports_AddStream(t *testing.T) {
	_, _, _ = CreateTestStore(t)

	var exports Exports
	require.NoError(t, exports.Load(), "error loading")
	require.Zero(t, exports.Len())

	exports.Add(NewStreamExport("Super Foo", "foo", "Foo"))
	require.Equal(t, 1, exports.Len())
}

func TestExports_Load(t *testing.T) {
	_, _, _ = CreateTestStore(t)

	var exports Exports
	require.NoError(t, exports.Load(), "error loading")
	require.Zero(t, exports.Len())

	require.NoError(t, exports.Add(NewStreamExport("Super Foo", "foo.>", "Foo")))
	require.NoError(t, exports.Add(NewServiceExport("Bar", "bar", "Bar")))
	require.Equal(t, 2, exports.Len())
	require.NoError(t, exports.Store(), "saving")

	var exports2 Exports
	require.NoError(t, exports2.Load(), "error loading 2")
	require.Equal(t, 2, exports2.Len())
}

func TestExports_NoDuplicateStreamSubjects(t *testing.T) {
	var exports Exports
	err := exports.Add(NewStreamExport("Foo", "foo", "Foo", "Stream"))
	require.NoError(t, err)
	err = exports.Add(NewStreamExport("Foo", "foo", "Foo", "Stream"))
	require.Error(t, err)
}

func TestExports_NoDuplicateServiceSubjects(t *testing.T) {
	var exports Exports
	err := exports.Add(NewServiceExport("Bar", "foo", "Foo", "Stream"))
	require.NoError(t, err)
	err = exports.Add(NewServiceExport("Bar", "foo", "Foo", "Stream"))
	require.Error(t, err)
}

func TestExports_NoDuplicateSubjects(t *testing.T) {
	var exports Exports
	err := exports.Add(NewStreamExport("Bar", "foo", "Foo", "Stream"))
	require.NoError(t, err)
	err = exports.Add(NewServiceExport("Bar", "foo", "Foo", "Service"))
	require.Error(t, err)
}

func TestExports_MatchTag(t *testing.T) {
	var exports Exports
	err := exports.Add(NewStreamExport("Foo", "foo", "Foo", "Stream", "Test"))
	require.NoError(t, err)
	err = exports.Add(NewServiceExport("Bar", "bar", "Bar", "Service", "Test"))
	require.NoError(t, err)
	err = exports.Add(NewServiceExport("FooBar", "foobar", "Foo", "Bar", "Service", "Production"))
	require.NoError(t, err)

	found := exports.Match("Test")
	require.Len(t, found, 2)
}

func TestExports_MatchName(t *testing.T) {
	var exports Exports
	err := exports.Add(NewStreamExport("Foo", "foo"))
	require.NoError(t, err)
	err = exports.Add(NewServiceExport("Bar", "bar"))
	require.NoError(t, err)
	err = exports.Add(NewServiceExport("FooBar", "foobar"))
	require.NoError(t, err)

	found := exports.Match("Foo")
	require.Len(t, found, 2)
}

func TestExports_MatchSubject(t *testing.T) {
	var exports Exports
	err := exports.Add(NewStreamExport("Foo", "foo"))
	require.NoError(t, err)
	err = exports.Add(NewServiceExport("Bar", "bar"))
	require.NoError(t, err)
	err = exports.Add(NewServiceExport("FooBar", "foobar"))
	require.NoError(t, err)

	found := exports.Match("foo")
	require.Len(t, found, 2)
}

func TestExports_Find(t *testing.T) {
	var exports Exports
	err := exports.Add(NewStreamExport("Foo", "foo", "Foo", "Stream", "Test"))
	require.NoError(t, err)
	err = exports.Add(NewServiceExport("Bar", "bar", "Bar", "Service", "Test"))
	require.NoError(t, err)
	err = exports.Add(NewServiceExport("FooBar", "foobar", "Foo", "Bar", "Service", "Production"))
	require.NoError(t, err)

	found := exports.Find("bar")
	require.NotNil(t, found)
	require.Equal(t, "Bar", found.Name)
}

func TestExports_ServicesContainNoWildcards(t *testing.T) {
	var exports Exports
	err := exports.Add(NewServiceExport("Foo", "foo>", "Foo", "Stream", "Test"))
	require.NoError(t, err)
	err = exports.Add(NewServiceExport("Foo", "foo*", "Foo", "Stream", "Test"))
	require.NoError(t, err)
	err = exports.Add(NewServiceExport("Foo", "foo.test*.bar", "Foo", "Stream", "Test"))
	require.NoError(t, err)
	err = exports.Add(NewServiceExport("Foo", "foo.*", "Foo", "Stream", "Test"))
	require.Error(t, err)
	err = exports.Add(NewServiceExport("Foo", "foo.>", "Foo", "Stream", "Test"))
	require.Error(t, err)
	err = exports.Add(NewServiceExport("Foo", "foo.*.bar", "Foo", "Stream", "Test"))
	require.Error(t, err)
}

func TestExports_Remove(t *testing.T) {
	var exports Exports
	err := exports.Add(NewServiceExport("Foo", "t", "Foo", "Stream", "Test"))
	require.NoError(t, err)
	require.Len(t, exports, 1)

	m := exports.Find("t")
	exports.Remove(m)
	require.Len(t, exports, 0)
}
