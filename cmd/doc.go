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
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var docCmd = &cobra.Command{
	Use:   "doc",
	Short: "Generate full man pages or markdown documentation",
	RunE: func(cmd *cobra.Command, args []string) error {
		if dp.man {
			d := filepath.Join(dp.outputDir, "ngs_man_doc")
			if err := os.MkdirAll(d, 0777); err != nil {
				return err
			}
			if err := doc.GenManTree(rootCmd, nil, d); err != nil {
				return err
			}
			cmd.Printf("Success! - generated man documentation in %q\n", d)
		}
		if dp.markdown {
			d := filepath.Join(dp.outputDir, "ngs_md_doc")
			if err := os.MkdirAll(d, 0777); err != nil {
				return err
			}
			if err := doc.GenMarkdownTree(rootCmd, d); err != nil {
				return err
			}
			cmd.Printf("Success! - generated markdown documentation in %q\n", d)
		}
		return nil
	},
}

type DocParams struct {
	outputDir string
	man       bool
	markdown  bool
}

func (p *DocParams) Validate() error {
	if !p.man && !p.markdown {
		return errors.New("specify format --man or --markdown")
	}
	return nil
}

var dp DocParams

func init() {
	settingsCmd.AddCommand(docCmd)
	docCmd.Flags().BoolVarP(&dp.man, "man", "", false, "Generate a man page")
	docCmd.Flags().BoolVarP(&dp.markdown, "markdown", "", false, "Generate markdown")
	docCmd.Flags().StringVarP(&dp.outputDir, "output-dir", "o", "./", "directory where documentation will be generated (default is current directory)")
}
