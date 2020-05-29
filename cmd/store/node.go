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

import "errors"

type Node struct {
	Parent   *Node
	Data     interface{}
	Children []*Node
}

func NewNode(data interface{}) *Node {
	return &Node{Data: data}
}

func (n *Node) Add(cn *Node) *Node {
	cn.Parent = n
	n.Children = append(n.Children, cn)
	return cn
}

func (n *Node) Delete() {
	if n.Parent != nil {
		for i, c := range n.Parent.Children {
			if c == n {
				l := n.Parent.Children[:i]
				r := n.Parent.Children[i+1:]
				n.Parent.Children = append(l, r...)
			}
		}
	}
}

var ErrSkipChildren = errors.New("skip node")
var ErrStopWalking = errors.New("found node")

type WalkFunc func(*Node) error

func Walk(root *Node, walkFn WalkFunc) error {
	err := walkFn(root)
	if err == nil {
		err = walk(root, walkFn)
	}
	if err == ErrSkipChildren || err == ErrStopWalking {
		return nil
	}
	return err
}

func walk(n *Node, walkFn WalkFunc) error {
	for _, c := range n.Children {
		err := walkFn(c)
		if err != nil {
			if err == ErrSkipChildren {
				continue
			} else if err == ErrStopWalking {
				return err
			} else {
				return err
			}
		} else {
			err = walk(c, walkFn)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
