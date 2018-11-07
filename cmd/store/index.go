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
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Tag is a key value pair
type Tag struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Normalize a tag so key and values are all lower-case
func (t *Tag) Normalize() {
	t.Key = strings.ToLower(t.Key)
	t.Value = strings.ToLower(t.Value)
}

// Index is contains columns that associate tags with paths
type Index struct {
	sync.Mutex
	store *Store
	data  map[string]*Column
}

// NewIndex returns an index for a store
func NewIndex(store *Store) *Index {
	var v Index
	v.store = store
	v.data = make(map[string]*Column)
	return &v
}

// Index the specified path to the provided tags
func (i *Index) Index(tokenID string, tag ...Tag) error {
	i.Lock()
	defer i.Unlock()

	rdx := i.getColumn("_rev")
	for _, v := range tag {
		v.Normalize()
		idx := i.getColumn(v.Key)
		idx.Add(v.Value, tokenID)
		rdx.Add(tokenID, fmt.Sprintf("%s,%s", v.Key, v.Value))
	}

	return nil
}

// Delete a path from the index
func (i *Index) Delete(tokenID string) error {
	i.Lock()
	defer i.Unlock()

	rdx := i.getColumn("_rev")
	tags := rdx.Get(tokenID)
	for _, kv := range tags {
		a := strings.Split(kv, ",")
		idx := i.getColumn(a[0])
		idx.Delete(a[1], tokenID)
	}
	return nil
}

// Returns all paths matching the specified tag
func (i *Index) Get(tag Tag) []string {
	tag.Normalize()
	idx := i.getColumn(tag.Key)
	return idx.data[tag.Value]
}

//Intersect returns all the rows that matched all tags
func (i *Index) Intersect(tag ...Tag) []string {
	var buf resultSets
	for _, v := range tag {
		v.Normalize()
		var rs resultSet
		d := i.Get(v)
		if d == nil {
			return nil
		}
		rs.data = d
		rs.Tag = v
		rs.len = len(d)
		buf = append(buf, rs)
	}
	sort.Sort(buf)

	var inAll []string
	small := buf[0]
	buf = buf[1:]
	for _, s := range small.data {
		for _, a := range buf {
			idx := sort.SearchStrings(a.data, s)
			if a.data[idx] != s {
				break
			}
		}
		inAll = append(inAll, s)
	}
	return inAll
}

// getColumn returns the index for a column associated with a tag name
func (i *Index) getColumn(n string) *Column {
	c := i.data[n]
	if c == nil {
		c = NewColumn(n, i.store)
		c.Load()
		i.data[n] = c
	}
	return c
}

// Save the index
func (i *Index) Save() error {
	for _, v := range i.data {
		if v.edited {
			if err := v.Close(); err != nil {
				return err
			}
		}
	}
	return nil
}

// Close the index
func (i *Index) Close() error {
	return i.Save()
}

// Column is a named after a tag name and contains entries
// for all the values under that tag
type Column struct {
	name   string
	store  *Store
	edited bool
	data   map[string][]string
}

// NewColumn creates a named Column in the store
func NewColumn(name string, s *Store) *Column {
	var v Column
	v.store = s
	v.name = name
	v.data = make(map[string][]string)
	return &v
}

// path calculates the location of the index given the column name
func (c *Column) path() string {
	return filepath.Join("indexes", c.name+".idx")
}

// Load a column from data in its corresponding file
func (c *Column) Load() error {
	fp := c.path()
	if c.store.Has(fp) {
		return c.store.ReadEntry(fp, &c.data)
	}
	return nil
}

// Adds a term to the column associated with the path
func (c *Column) Add(term string, path string) {
	a := c.data[term]
	idx := sort.SearchStrings(a, path)
	if idx == len(a) {
		a = append(a, path)
	} else if a[idx] == path {
		return
	} else if idx == 0 {
		a = append([]string{path}, a...)
	} else {
		b := append([]string{path}, a[idx+1:]...)
		a = append(a[:idx], b...)
	}

	c.edited = true
	c.data[term] = a
}

// Deletes a reference from the term entries
func (c *Column) Delete(term string, reference string) {
	a := c.data[term]
	if a == nil {
		return
	}
	for i, v := range a {
		if v == reference {
			c.edited = true
			a = append(a[:i], a[i+1:]...)
		}
	}
	c.data[term] = a
}

// Get all the entries under term
func (c *Column) Get(term string) []string {
	return c.data[term]
}

// Save a column to disk
func (c *Column) Save() error {
	return c.store.WriteEntry(c.path(), &c.data)
}

// Close the column
func (c *Column) Close() error {
	return c.Save()
}

type resultSet struct {
	Tag
	data []string
	len  int
}

type resultSets []resultSet

// Number of resultSet in the resultSet - sort support
func (b resultSets) Len() int {
	return len(b)
}

// Swap resultSet in the resultSet - sort support
func (b resultSets) Swap(i, j int) {
	b[i], b[j] = b[j], b[i]
}

// Less returns true if the result set in i has less entries that j
func (b resultSets) Less(i, j int) bool {
	return len(b[i].data) < len(b[j].data)
}
