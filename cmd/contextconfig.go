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
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"

	"github.com/nats-io/nsc/cmd/store"
)

type ContextConfig struct {
	StoreRoot string `json:"store_root"` // where the projects are
	Operator  string `json:"operator"`
	Account   string `json:"account"`
	Cluster   string `json:"cluster"`
}

func NewContextConfig(storeRoot string) (*ContextConfig, error) {
	var err error
	ctx := ContextConfig{}
	if storeRoot != "" {
		ctx.StoreRoot, err = filepath.Abs(storeRoot)
		if err != nil {
			return nil, err
		}
		ctx.SetDefaults()
	}
	return &ctx, nil
}

// deduce as much context as possible
func (c *ContextConfig) SetDefaults() {
	if err := IsValidDir(c.StoreRoot); err == nil {
		operators := c.ListOperators()
		c.Operator = c.saneDefault(c.Operator, operators)
		if c.Operator == "" {
			// reset everything
			c.Account = ""
			c.Cluster = ""
			return
		}

		s, err := c.LoadStore(c.Operator)
		if err != nil {
			return
		}
		accounts, err := s.ListSubContainers(store.Accounts)
		if err == nil {
			c.Account = c.saneDefault(c.Account, accounts)
		}
		clusters, err := s.ListSubContainers(store.Clusters)
		if err == nil {
			c.Cluster = c.saneDefault(c.Cluster, clusters)
		}
	}
}

// saneDefault keeps the current choice if it exists, or returns ""
func (c *ContextConfig) saneDefault(current string, choices []string) string {
	switch len(choices) {
	case 0:
		return ""
	case 1:
		return choices[0]
	default:
		for _, v := range choices {
			if v == current {
				return current
			}
		}
		return ""
	}
}

func (c *ContextConfig) LoadStore(operatorName string) (*store.Store, error) {
	return store.LoadStore(filepath.Join(c.StoreRoot, operatorName))
}

func (c *ContextConfig) ListOperators() []string {
	infos, err := ioutil.ReadDir(c.StoreRoot)
	if err != nil {
		return nil
	}
	var operators []string
	for _, v := range infos {
		name := store.SafeName(filepath.Base(v.Name()))
		fp := filepath.Join(c.StoreRoot, name, store.NSCFile)
		info, err := os.Stat(fp)
		if err == nil && info != nil {
			operators = append(operators, v.Name())
		}
	}
	sort.Strings(operators)
	return operators
}

func (c *ContextConfig) SetOperator(operator string) error {
	for _, v := range c.ListOperators() {
		if v == operator {
			c.Operator = operator
			return nil
		}
	}
	return fmt.Errorf("operator %q not in %q", operator, c.StoreRoot)
}

func (c *ContextConfig) SetAccount(account string) error {
	if err := c.hasSubContainer(store.Accounts, account); err != nil {
		return err
	}
	c.Account = account
	return nil
}

func (c *ContextConfig) SetCluster(cluster string) error {
	if err := c.hasSubContainer(store.Clusters, cluster); err != nil {
		return err
	}
	c.Cluster = cluster
	return nil
}

func (c *ContextConfig) ListAccounts() ([]string, error) {
	return c.getSubContainers(store.Accounts)
}

func (c *ContextConfig) ListClusters() ([]string, error) {
	return c.getSubContainers(store.Clusters)
}

func (c *ContextConfig) getSubContainers(kind string) ([]string, error) {
	s, err := store.LoadStore(filepath.Join(c.StoreRoot, c.Operator))
	if err != nil {
		return nil, err
	}
	names, err := s.ListSubContainers(kind)
	if err != nil {
		return nil, err
	}
	return names, nil
}

func (c *ContextConfig) hasSubContainer(kind string, name string) error {
	names, err := c.getSubContainers(kind)
	if err != nil {
		return err
	}
	for _, v := range names {
		if name == v {
			return nil
		}
	}
	return fmt.Errorf("%q not in %s for operator %q in %q", name, kind, c.Operator, c.StoreRoot)
}
