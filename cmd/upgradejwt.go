// Copyright 2018-2020 The NATS Authors
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

package cmd

import (
	"archive/zip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nats-io/nkeys"

	"github.com/nats-io/cliprompts/v2"

	"github.com/nats-io/nsc/v2/cmd/store"
	"github.com/spf13/cobra"
)

func backup(file string, dir string) error {
	fp, err := os.Create(file)
	if err != nil {
		return err
	}
	defer fp.Close()
	w := zip.NewWriter(fp)
	defer w.Close()
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		wrtr, err := w.Create(strings.TrimPrefix(path, dir))
		if err != nil {
			return err
		}
		dat, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		_, err = wrtr.Write(dat)
		if err != nil {
			return err
		}
		return nil
	})
}

const upgradeQuestion = `Did you upgrade all nats-server and do you want to convert all non managed 
operator / account / user jwt to V2?
Once converted you need to re-distribute the operator jwt wherever used.
This includes, but is not limited to:
    ALL nats-server, which need to be restarted (one by one is ok)
    ALL dependent nsc stores in managed mode
`

func upgradeOperator(cmd *cobra.Command, s *store.Store, rep *store.Report) {
	op, err := s.ReadOperatorClaim()
	if err != nil {
		rep.AddError(`Could not find Operator, please check your environment using "nsc env"`)
		return
	}
	opName := op.Name
	// check for Version > 2 happens in root
	if op.Version == 2 {
		rep.AddOK("Operator %s is already upgraded to version %d. No change was applied", opName, op.Version)
		return
	}
	if s.IsManaged() {
		cmd.Print(cliprompts.WrapString(80, upgradeQuestion))
		rep.AddError(`No change was made! Your store is in managed mode and was set up using:
"nsc add operator --force --url <file or url>""
You need to contact "%s", obtain a V2 jwt and re issue the above command.
`, opName)
		return
	}
	// obtain private identity key needed to recode the operator jwt
	var opKp nkeys.KeyPair
	if ctx, err := s.GetContext(); err != nil {
		rep.AddError("Loading Operator Context %s failed: %v", opName, err)
	} else {
		opKp, err = ctx.KeyStore.GetKeyPair(op.Subject)
		if opKp == nil {
			errString := "not found"
			if err != nil {
				errString = fmt.Sprintf("failed with error: %v", err)
			}
			rep.AddError(`Identity Key for Operator %s %s.
This key needs to be present in order to rewrite the Operator to be v2.
If you intentionally removed it, you need to restore it for this command to work.`, opName, errString)
		}
	}
	if opKp == nil {
		return
	}
	if conv, _ := cliprompts.Confirm(cliprompts.WrapString(80, `It is advisable to create a backup of the store.
Do you want to create a backup in the form of a zip file now?`), true); conv {
		dir, _ := os.Getwd()
		zipFileDefault := filepath.Join(dir, fmt.Sprintf("%s-jwtV1-upgrade-backup.zip", opName))
		backupFile, err := cliprompts.Prompt("zip file name:", zipFileDefault)
		if err != nil {
			rep.AddError("Error obtaining file name")
			return
		}
		if err = backup(backupFile, s.Dir); err != nil {
			rep.AddError("Error creating backup zip file")
			return
		}
		cmd.Print(cliprompts.WrapSprintf(80, `Backup file "%s" created. 
This backup does `+cliprompts.Bold("not contain private nkeys")+`!
`+cliprompts.Bold("If you need to restore this state")+`:
	Delete the directory "%s"
	Extract the backup 
	Move the created directory in place of the deleted one
	Downgrade nsc using: "nsc update -version 0.5.0"
`, backupFile, s.Dir))
	}
	cmd.Print(cliprompts.WrapString(80,
		`In order to use jwt V2, `+cliprompts.Bold("you must upgrade all nats-server")+` prior to usage!
If you are `+cliprompts.Bold("not ready")+` to switch over to jwt V2, downgrade nsc using:
"nsc update -version 0.5.0"
`))
	if conv, _ := cliprompts.Confirm(cliprompts.WrapString(80, upgradeQuestion), false); !conv {
		rep.AddOK("Declined to convert at this time. Rerun command when ready.")
		return
	}
	if newJwt, err := op.Encode(opKp); err != nil {
		rep.AddError("Re-Encoding Operator jwt %s failed: %v", opName, err)
	} else if _, err = s.StoreClaim([]byte(newJwt)); err != nil {
		rep.AddError("Storing Re-Encoded Operator jwt %s failed: %v", opName, err)
	} else {
		rep.AddOK("Converted Operator: %s", opName)
	}
}

func createUpgradeJwtCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Example: "nsc upgrade-jwt",
		Use:     "upgrade-jwt",
		Short:   "Update jwt w",
		Args:    MaxArgs(0),
		Hidden:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			config := GetConfig()
			if config.StoreRoot == "" {
				return errors.New("no store set - `env --store <dir>`")
			}
			rep := store.Report{Label: "Upgrade operator jwt to v2"}
			s, err := GetStore()
			if err != nil {
				return err
			}
			upgradeOperator(cmd, s, &rep)
			cmd.Print(rep.Message())
			return nil
		},
	}
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createUpgradeJwtCommand())
}
