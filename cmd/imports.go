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
	"fmt"
	"strings"

	"github.com/nats-io/jwt"
	"github.com/nats-io/nsc/cmd/store"
	"github.com/xlab/tablewriter"
)

type Imports []*Import

type Import struct {
	JTI string      `json:"jti"`
	Map jwt.Subject `json:"prefix"`
	Export
}

func (e *Import) String() string {
	return fmt.Sprintf("%s\t%v\t%s\t%s", DefaultName(e.Name), e.Type, e.Subject, strings.Join(e.Tag, ","))
}

func (e *Imports) Load() error {
	s, err := getStore()
	if err != nil {
		return fmt.Errorf("error loading store: %v", err)
	}
	if s.Has(store.Imports) {
		return s.ReadEntry(store.Imports, &e)
	}
	return nil
}

func (e *Imports) Match(term string) Imports {
	var buf []*Import
	for _, t := range *e {
		if t.Matches(term) {
			buf = append(buf, t)
		}
	}
	return buf
}

func (e *Imports) Store() error {
	s, err := getStore()
	if err != nil {
		return fmt.Errorf("error loading store: %v", err)
	}
	return s.WriteEntry(store.Imports, e)
}

func (e *Imports) Contains(i *Import) bool {
	for _, v := range *e {
		if v.Subject == i.Subject && v.JTI == i.JTI {
			return true
		}
	}
	return false
}

func (e *Imports) Add(a ...*Import) error {
	for _, v := range a {
		if e.Contains(v) {
			return fmt.Errorf("import already exists")
		}
	}
	*e = append(*e, a...)
	return nil
}

func (e *Imports) Remove(p ...*Import) {
	for _, v := range p {
		for i, t := range *e {
			if t.Subject == v.Subject && t.JTI == v.JTI {
				a := *e
				*e = append(a[:i], a[i+1:]...)
				break
			}
		}
	}
}

func PrintImports(exports []*Import) {
	table := tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle("Imported Services")
	table.AddHeaders("Name", "Type", "Subject", "To", "Tags")
	for _, v := range exports {
		if v.IsService() {
			table.AddRow(v.Name, v.Type, v.Subject, v.Map, strings.Join(v.Tag, ","))
		}
	}
	fmt.Println(table.Render())

	table = tablewriter.CreateTable()
	table.UTF8Box()
	table.AddTitle("Imported Streams")
	table.AddHeaders("Name", "Type", "Subject", "Prefix", "Tags")

	for _, v := range exports {
		if v.IsStream() {
			table.AddRow(v.Name, v.Type, v.Subject, v.Map, strings.Join(v.Tag, ","))
		}
	}
	fmt.Println(table.Render())
}
