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
	"fmt"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/nats-io/jwt"
	"github.com/spf13/cobra"
	"github.com/xlab/tablewriter"
)

func createListActivationsCmd() *cobra.Command {
	var params ListActivationsParams
	var cmd = &cobra.Command{
		Use:   "activations",
		Short: "List activations",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := getStore()
			if err != nil {
				return fmt.Errorf("error generating account jwt: %v", err)
			}

			var activations []string
			ngsA, err := s.GetAccountActivation()
			if err != nil {
				return err
			}
			activations = append(activations, ngsA)

			other, err := ListActivations()
			if err != nil {
				return fmt.Errorf("error loading activations: %v\n", err)
			}
			activations = append(activations, other...)
			if len(activations) == 0 {
				return errors.New("no activations found")
			}

			table := tablewriter.CreateTable()
			table.UTF8Box()
			table.AddTitle("Activations")
			table.AddHeaders("Name", "JTI", "Expiration")
			for _, act := range activations {
				claim, err := jwt.DecodeActivationClaims(act)
				if err != nil {
					return fmt.Errorf("error parsing activation: %v", err)
				}
				table.AddRow(DefaultName(claim.Name), claim.ID, UnixToDate(claim.Expires))
			}
			Write(params.outputFile, []byte(table.Render()))

			if !IsStdOut(params.outputFile) {
				cmd.Printf("Success! - wrote activation to %q\n", params.outputFile)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&params.outputFile, "output-file", "o", "--", "print results to the output file - stdout specify '--'")
	return cmd
}

func init() {
	listCmd.AddCommand(createListActivationsCmd())
}

func UnixToDate(d int64) string {
	if d == 0 {
		return ""
	}
	now := time.Now()
	when := time.Unix(d, 0).UTC()

	if now.After(when) {
		return strings.Title(humanize.RelTime(when, now, "ago", ""))
	} else {
		return strings.Title("in " + humanize.RelTime(now, when, "", ""))
	}
}

func TimeToExpiration(d int64) string {
	if d == 0 {
		return ""
	}
	return time.Until(time.Unix(d, 0)).String()
}

type ListActivationsParams struct {
	outputFile string
}
