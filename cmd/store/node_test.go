// Copyright 2018 The NATS Authors
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

	"github.com/stretchr/testify/require"
)

func TestNode_Walk(t *testing.T) {
	root := NewNode("/")
	a := root.Add(NewNode("A"))
	a.Add(NewNode("AA"))
	a.Add(NewNode("BB"))

	var visited []interface{}
	Walk(root, func(n *Node) error {
		visited = append(visited, n.Data)
		return nil
	})

	require.Len(t, visited, 4)
	require.ElementsMatch(t, visited, []string{"/", "A", "AA", "BB"})
}

func TestNode_WalkFind(t *testing.T) {
	root := NewNode("/")
	a := root.Add(NewNode("A"))
	a.Add(NewNode("AA"))
	a.Add(NewNode("BB"))

	var visited []interface{}
	Walk(root, func(n *Node) error {
		visited = append(visited, n.Data)
		if n.Data == "A" {
			return ErrStopWalking
		}
		return nil
	})

	require.Len(t, visited, 2)
	require.ElementsMatch(t, visited, []string{"/", "A"})
}

func TestNode_WalkSkipChildren(t *testing.T) {
	root := NewNode("/")
	a := root.Add(NewNode("A"))
	a.Add(NewNode("AA"))
	a.Add(NewNode("aa"))

	b := root.Add(NewNode("B"))
	b.Add(NewNode("BB"))

	var visited []interface{}
	Walk(root, func(n *Node) error {
		visited = append(visited, n.Data)
		if n.Data == "A" {
			return ErrSkipChildren
		}
		return nil
	})

	require.Len(t, visited, 4)
	require.ElementsMatch(t, visited, []string{"/", "A", "B", "BB"})
}

func TestNode_Parents(t *testing.T) {
	root := NewNode("/")
	a := root.Add(NewNode("A"))
	a.Add(NewNode("AA"))
	a.Add(NewNode("aa"))

	b := root.Add(NewNode("B"))
	b.Add(NewNode("BB"))

	var visited []interface{}
	var found *Node
	Walk(root, func(n *Node) error {
		visited = append(visited, n.Data)
		if n.Data == "A" {
			found = n
			return ErrStopWalking
		}
		return nil
	})

	require.Len(t, visited, 2)
	require.ElementsMatch(t, visited, []string{"/", "A"})

	require.NotNil(t, found)
	require.Equal(t, found.Parent, root)
}

func TestNode_Delete(t *testing.T) {
	root := NewNode("/")
	a := root.Add(NewNode("A"))
	a.Add(NewNode("AA"))
	a.Add(NewNode("aa"))
	b := root.Add(NewNode("B"))
	b.Add(NewNode("BB"))

	a.Delete()

	var visited []interface{}
	Walk(root, func(n *Node) error {
		visited = append(visited, n.Data)
		return nil
	})

	require.Len(t, visited, 3)
	require.ElementsMatch(t, visited, []string{"/", "B", "BB"})
}

func TestNode_DeleteLast(t *testing.T) {
	root := NewNode("/")
	a := root.Add(NewNode("A"))
	a.Add(NewNode("AA"))
	aa := a.Add(NewNode("aa"))
	b := root.Add(NewNode("B"))
	b.Add(NewNode("BB"))

	aa.Delete()

	var visited []interface{}
	Walk(root, func(n *Node) error {
		visited = append(visited, n.Data)
		return nil
	})

	require.Len(t, visited, 5)
	require.ElementsMatch(t, visited, []string{"/", "A", "AA", "B", "BB"})
}
