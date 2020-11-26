/*
 * Copyright 2018-2020 The NATS Authors
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

	"github.com/nats-io/cliprompts/v2"
	"github.com/nats-io/nsc/cmd/store"

	"github.com/spf13/cobra"
)

func createUpgradeJwtCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Example: "nsc upgrade-jwt",
		Use:     "upgrade-jwt",
		Short:   "Update jwt w",
		Args:    MaxArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			config := GetConfig()
			if config.StoreRoot == "" {
				return errors.New("no store set - `env --store <dir>`")
			}
			rep := store.Report{}
			operators := config.ListOperators()
			if len(operators) == 0 {
				return errors.New("no operators defined - init an environment")
			}
			cmd.Print(cliprompts.WrapString(80,
				`In order to use jwt V2, `+cliprompts.Bold("YOU MUST UPGRADE ALL nats-server")+` prior to usage!
If you are not ready to switch over to jwt V2 downgrade nsc using:
"nsc update -version <previous release>"

`))
			if conv, err := cliprompts.Confirm(cliprompts.WrapString(80,
				`DID YOU UPGRADE nats-server AND DO YOU WANT TO CONVERT ALL NON MANAGED 
OPERATOR / ACCOUNTS / USER JWT TO V2?`), false); err != nil {
				return err
			} else if !conv {
				rep.AddOK("Declined to convert at this time. Rerun command when ready.")
				cmd.Print(rep.Message())
				return nil
			}
			rep.AddOK("Inspecting all Operator(s)")
			for _, opName := range operators {
				if s, err := config.LoadStore(opName); err != nil {
					rep.AddError("Loading Operator Store %s failed: %v", opName, err)
				} else if op, err := s.ReadOperatorClaim(); err != nil {
					rep.AddError("Reading Operator Claim %s failed: %v", opName, err)
				} else if ctx, err := s.GetContext(); err != nil {
					rep.AddError("Loading Operator Context %s failed: %v", opName, err)
				} else {
					if op.Version == 1 {
						if kp, err := ctx.KeyStore.GetKeyPair(op.Issuer); err != nil {
							rep.AddError("Loading Operator Issuer Key %s failed: %v", opName, err)
						} else if kp == nil {
							if s.IsManaged() {
								rep.AddOK("Skipping Managed Operator %s", opName)
							} else {
								rep.AddError("Loading Operator Issuer Key %s failed: not found", opName)
							}
						} else if newJwt, err := op.Encode(kp); err != nil {
							rep.AddError("Re-Encoding Operator jwt %s failed: %v", opName, err)
						} else if _, err = s.StoreClaim([]byte(newJwt)); err != nil {
							rep.AddError("Storing Re-Encoded Operator jwt %s failed: %v", opName, err)
						} else {
							rep.AddOK("Converted Operator: %s", opName)
						}
					}
					accs, _ := s.ListSubContainers(store.Accounts)
					for _, accSubj := range accs {
						accName := ""
						if ac, err := s.ReadAccountClaim(accSubj); err != nil {
							rep.AddError("Operator %s: Reading Account Claim %s failed: %v", opName, accSubj, err)
						} else if accName = ac.Name; ac.Version == 1 {
							if kp, err := ctx.KeyStore.GetKeyPair(ac.Issuer); err != nil {
								rep.AddError("Operator %s: Loading Issuer Key %s of Account %s failed: %v", opName, ac.Issuer, accName, err)
							} else if kp == nil {
								if s.IsManaged() {
									rep.AddOK("Operator %s: Skipping Managed Account %s", opName, accName)
								} else {
									rep.AddError("Operator %s: Loading Issuer Key %s of Account %s failed: not found", opName, ac.Issuer, accName)
								}
							} else if newJwt, err := ac.Encode(kp); err != nil {
								rep.AddError("Operator %s: Re-Encoding Account jwt %s failed: %v", opName, accName, err)
							} else if _, err = s.StoreClaim([]byte(newJwt)); err != nil {
								rep.AddError("Operator %s: Storing Re-Encoded Account jwt %s failed: %v", opName, accName, err)
							} else {
								rep.AddOK("Operator %s: Converted Account: %s", opName, accName)
							}
						}
						if names, err := s.ListEntries(store.Accounts, accName, store.Users); err != nil {
							rep.AddError("Account %s: Listing Users failed: %v", accName, err)
							continue
						} else {
							for _, usrName := range names {
								uc, err := s.ReadUserClaim(accName, usrName)
								if err != nil {
									rep.AddError("Account %s: Reading User Claim %s failed: %v", usrName, accName, err)
								} else if uc.Version != 1 {
								} else if kp, err := ctx.KeyStore.GetKeyPair(uc.Issuer); err != nil {
									rep.AddError("Account %s: Loading Issuer Key of Claim %s failed: %v", accName, usrName, err)
								} else if kp == nil {
									rep.AddError("Account %s: Loading Issuer Key of Claim %s not found", accName, usrName)
								} else if newJwt, err := uc.Encode(kp); err != nil {
									rep.AddError("Account %s: Re-Encoding User Claim %s failed: %v", accName, usrName, err)
								} else if _, err = s.StoreClaim([]byte(newJwt)); err != nil {
									rep.AddError("Account %s: Storing Re-Encoded User jwt %s failed: %v", accName, usrName, err)
								} else {
									rep.AddOK("Account %s: Converted User: %s", accName, usrName)
								}
							}
						}
					}
				}
			}
			cmd.Print(rep.Message())
			return nil
		},
	}
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createUpgradeJwtCommand())
}
