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
	"errors"

	"github.com/spf13/cobra"
)

type ClusterContextParams struct {
	Name string
}

func (p *ClusterContextParams) BindFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&p.Name, "cluster", "c", "", "cluster name")
}

func (p *ClusterContextParams) SetDefaults(ctx ActionCtx) {
	if p.Name != "" && ctx.StoreCtx().Cluster.Name == "" {
		ctx.StoreCtx().Cluster.Name = p.Name
	}
	if ctx.StoreCtx().Cluster.Name != "" && p.Name == "" {
		p.Name = ctx.StoreCtx().Cluster.Name
	}
}

func (p *ClusterContextParams) Edit(ctx ActionCtx) error {
	var err error
	p.Name, err = ctx.StoreCtx().PickCluster(p.Name)
	if err != nil {
		return err
	}
	ctx.StoreCtx().Cluster.Name = p.Name
	return nil
}

func (p *ClusterContextParams) Validate(ctx ActionCtx) error {
	// default cluster was not found by get context, so we either we have none or many
	if p.Name == "" {
		ctx.CurrentCmd().SilenceUsage = false
		return errors.New("a cluster is required")
	}
	return nil
}
