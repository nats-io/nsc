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
	"bytes"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/xlab/tablewriter"
)

type Exports []*Export

func (e *Exports) Store() error {
	s, err := getStore()
	if err != nil {
		return fmt.Errorf("error loading store: %v", err)
	}
	return s.WriteEntry(store.Exports, e)
}

func (e *Exports) Load() error {
	s, err := getStore()
	if err != nil {
		return fmt.Errorf("error loading store: %v", err)
	}
	if s.Has(store.Exports) {
		return s.ReadEntry(store.Exports, &e)
	}
	return nil
}

func ListExports() (Exports, error) {
	var ex Exports
	if err := ex.Load(); err != nil {
		return nil, err
	}
	return ex, nil
}

func (e *Exports) Match(term string) Exports {
	var buf []*Export
	for _, t := range *e {
		if t.Matches(term) {
			buf = append(buf, t)
		}
	}
	return buf
}

func (e *Exports) Find(subject string) *Export {
	for _, t := range *e {
		if t.Subject == jwt.Subject(subject) {
			return t
		}
	}
	return nil
}

func (e *Exports) Len() int {
	return len(*e)
}

type Export struct {
	jwt.Export
	Tag jwt.StringList `json:"tag,omitempty"`
}

func NewServiceExport(name string, subject string, tags ...string) *Export {
	v := Export{}
	v.Type = jwt.ServiceType
	v.Name = name
	v.Subject = jwt.Subject(subject)
	v.Tag = tags
	return &v
}

func NewStreamExport(name string, subject string, tags ...string) *Export {
	v := Export{}
	v.Type = jwt.StreamType
	v.Name = name
	v.Subject = jwt.Subject(subject)
	v.Tag = tags
	return &v
}

func (e *Export) String() string {
	return fmt.Sprintf("%s\t%v\t%s\t%s", DefaultName(e.Name), e.Type, e.Subject, strings.Join(e.Tag, ","))
}

func (e *Export) Matches(term string) bool {
	if strings.Contains(e.Name, term) {
		return true
	}
	v := string(e.Subject)
	if strings.Contains(v, term) {
		return true
	}
	if strings.Contains(strings.Join(e.Tag, ""), term) {
		return true
	}
	return false
}

func (e *Export) Describe() []byte {
	buf := bytes.NewBuffer(nil)
	w := tabwriter.NewWriter(buf, 0, 8, 3, ' ', 0)
	fmt.Fprintf(w, "Name:\t%s\n", e.Name)
	fmt.Fprintf(w, "Type:\t%v\n", e.Type)
	fmt.Fprintf(w, "Subject:\t%s\n", e.Subject)
	if len(e.Tag) > 0 {
		fmt.Fprintf(w, "Tags:\t%s\n", strings.Join(e.Tag, ","))
	}
	w.Flush()
	return buf.Bytes()
}

func PrintExports(exports []*Export) {
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle("Exports")
	table.AddHeaders("Name", "Type", "Subject", "Tags")
	for _, v := range exports {
		table.AddRow(v.Name, v.Type, v.Subject, strings.Join(v.Tag, ","))
	}
	fmt.Println(table.Render())
}

func (e *Exports) Contains(s *Export) bool {
	for _, v := range *e {
		if v.Subject == s.Subject {
			return true
		}
	}
	return false
}

func (e *Exports) Add(p ...*Export) error {
	for _, s := range p {
		if s.IsService() && s.Subject.HasWildCards() {
			return fmt.Errorf("services cannot contain wildcards")
		}
		if e.Contains(s) {
			return fmt.Errorf("a stream or service with subject %q exists already", s.Subject)
		}
	}
	*e = append(*e, p...)
	return nil
}

// FIXME: this doesn't do the right thing
func (e *Exports) Remove(p ...*Export) {
	for _, v := range p {
		for i, t := range *e {
			if t.Subject == v.Subject {
				a := *e
				*e = append(a[:i], a[i+1:]...)
				break
			}
		}
	}
}
