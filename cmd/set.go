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
	"github.com/spf13/cobra"
)

func createSetContextCmd() *cobra.Command {
	var params SetContextParams
	cmd := &cobra.Command{
		Use:          "set",
		Short:        "Set the context for the stores, operator, account or cluster",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {

			copy := *GetConfig()

			//var err error
			//if params.StoreRoot != "" {
			//	params.StoreRoot, err = filepath.Abs(params.StoreRoot)
			//	if err != nil {
			//		return err
			//	}
			//	if err = IsValidDir(params.StoreRoot); err != nil {
			//		return err
			//	}
			//	copy.StoreRoot = params.StoreRoot
			//}
			//
			//if params.Operator != "" {
			//	copy.Operator = store.SafeName(params.Operator)
			//}
			//
			//if copy.Operator == "" {
			//	infos, err := ioutil.ReadDir(copy.StoreRoot)
			//	if err != nil {
			//		return fmt.Errorf("error listing %q: %v", params.StoreRoot, err)
			//	}
			//	var operators []string
			//	for _, v := range infos {
			//		name := store.SafeName(filepath.Base(v.Name()))
			//		fp := filepath.Join(copy.StoreRoot, name, store.NSCFile)
			//		info, err := os.Stat(fp)
			//		if err == nil && info != nil {
			//			operators = append(operators, v.Name())
			//		}
			//	}
			//
			//	if len(operators) == 0 {
			//		return fmt.Errorf("no operators in %q", params.StoreRoot)
			//	}
			//	if len(operators) == 1 {
			//		copy.Operator =
			//	}
			//}
			//
			//s, err := store.LoadStore(sp)
			//if err != nil {
			//	return err
			//}
			//
			//if params.Account != "" {
			//	copy.Account = store.SafeName(params.Account)
			//
			//	accounts, err := s.ListEntries(store.Accounts)
			//	if err != nil {
			//		return err
			//	}
			//	found := false
			//	for _, v := range accounts {
			//		if copy.Account == v {
			//			found = true
			//			break
			//		}
			//	}
			//	if !found {
			//		return fmt.Errorf("account %q is not contained by operator %q", copy.Account, copy.Operator)
			//	}
			//}
			//
			//if params.Cluster != "" {
			//	copy.Cluster = store.SafeName(params.Cluster)
			//
			//	clusters, err := s.ListEntries(store.Clusters)
			//	if err != nil {
			//		return err
			//	}
			//	found := false
			//	for _, v := range clusters {
			//		if copy.Cluster == v {
			//			found = true
			//			break
			//		}
			//	}
			//	if !found {
			//		return fmt.Errorf("cluster %q is not contained by operator %q", copy.Cluster, copy.Operator)
			//	}
			//}

			return copy.Save()
		},
	}

	cmd.Flags().StringVarP(&params.StoreRoot, "store", "s", "", "store directory")
	cmd.Flags().StringVarP(&params.StoreRoot, "operator", "o", "", "operator name")
	cmd.Flags().StringVarP(&params.StoreRoot, "account", "a", "", "account name")
	cmd.Flags().StringVarP(&params.StoreRoot, "cluster", "c", "", "cluster name")

	return cmd
}

func init() {
	rootCmd.AddCommand(createSetContextCmd())
}

type SetContextParams struct {
	StoreRoot string
	Operator  string
	Account   string
	Cluster   string
}
