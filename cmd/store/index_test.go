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

package store

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func initIndex(t *testing.T, s *Store) *Index {
	i := NewIndex(s)
	i.Index("foo", Tag{"color", "red"}, Tag{"name", "foo"})
	i.Index("bar", Tag{"color", "red"}, Tag{"name", "bar"})

	return i
}

func TestEmpty(t *testing.T) {
	s := InitStore(t)
	i := NewIndex(s)
	a := i.Get(Tag{"color", "red"})
	require.Nil(t, a)
}

func TestIndex(t *testing.T) {
	s := InitStore(t)
	i := initIndex(t, s)
	i.Save()

	// should match both
	a := i.Get(Tag{"color", "red"})
	require.ElementsMatch(t, a, []string{"foo", "bar"}, s.Dir)

	// should only find one
	a = i.Get(Tag{"name", "foo"})
	require.Contains(t, a, "foo")
	require.Len(t, a, 1)

	a = i.Intersect(Tag{"color", "red"}, Tag{"name", "foo"})
	require.Contains(t, a, "foo")
	require.Len(t, a, 1)

	if err := i.Close(); err != nil {
		t.Fatal("failed to close the index", err)
	}

	ii := NewIndex(s)

	// should match both
	a = ii.Get(Tag{"color", "red"})
	require.ElementsMatch(t, a, []string{"foo", "bar"})

	// should only find one
	a = ii.Get(Tag{"name", "foo"})
	require.Contains(t, a, "foo")
	require.Len(t, a, 1)

	a = ii.Intersect(Tag{"color", "red"}, Tag{"name", "foo"})
	require.Contains(t, a, "foo")
	require.Len(t, a, 1)
}

func TestDelete(t *testing.T) {
	s := InitStore(t)
	i := initIndex(t, s)

	// should match both
	a := i.Get(Tag{"color", "red"})
	require.ElementsMatch(t, a, []string{"foo", "bar"}, s.Dir)

	if err := i.Delete("foo"); err != nil {
		t.Fatal("error deleting", err, s.Dir)
	}

	a = i.Get(Tag{"color", "red"})
	i.Save()
	require.ElementsMatch(t, a, []string{"bar"}, s.Dir)

}
