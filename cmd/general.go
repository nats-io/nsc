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
	"strings"

	"github.com/nats-io/nsc/cli"
	"github.com/spf13/cobra"
)

type GenericParams struct {
	tags []string
}

func (p *GenericParams) BindFlags(cmd *cobra.Command) {
	cmd.Flags().StringSliceVarP(&p.tags, "tags", "", nil, "list of arbitrary strings (--tags a,b,c) - this flag can be specified multiple times")
}

func (p *GenericParams) Validate() error {
	return nil
}

func (p *GenericParams) Edit() error {
	s, err := cli.Prompt("comma separated list of tags", strings.Join(p.tags, ","), true, nil)
	if err != nil {
		return err
	}
	p.tags = strings.Split(s, ",")
	for i, v := range p.tags {
		p.tags[i] = strings.TrimSpace(v)
	}
	return nil
}
