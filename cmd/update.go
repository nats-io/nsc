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
	"time"

	"github.com/blang/semver"
	"github.com/briandowns/spinner"
	"github.com/nats-io/nsc/cli"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
	"github.com/spf13/cobra"
)

func createUpdateCommand() *cobra.Command {
	var printReleaseNotes bool
	var cmd = &cobra.Command{
		Example: `update
update --release-notes
`,
		Use:   "update",
		Short: "update this tool to latest version",
		RunE: func(cmd *cobra.Command, args []string) error {
			v := semver.MustParse(GetRootCmd().Version)

			su, err := NewSelfUpdate()
			if err != nil {
				return err
			}
			nvs, err := su.doCheck()
			if err != nil {
				return err
			}
			if nvs == nil {
				cmd.Println("Current version", v, "is the latest")
				return nil
			}

			wait := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
			defer wait.Stop()

			wait.Prefix = "Downloading latest version "
			_ = wait.Color("italic")
			wait.Start()
			latest, err := selfupdate.UpdateSelf(v, GetConfig().GithubUpdates)
			if err != nil {
				cmd.SilenceErrors = false
				return err
			}

			cmd.Printf("Successfully updated to version %s\n", latest.Version.String())
			if printReleaseNotes {
				cmd.Println()
				cmd.Println("Release Notes:")
				cmd.Println()
				cmd.Println(cli.Wrap(80, latest.ReleaseNotes))
			}

			return nil
		},
	}

	cmd.Flags().BoolVarP(&printReleaseNotes, "release-notes", "r", false, "prints the release notes")

	return cmd
}

func init() {
	GetRootCmd().AddCommand(createUpdateCommand())
}

type SelfUpdate struct {
}

// NewSelfUpdate creates a new self update object
func NewSelfUpdate() (*SelfUpdate, error) {

	if GetConfig().GithubUpdates == "" {
		return nil, fmt.Errorf("unable to check for updates - repository not set")
	}

	u := &SelfUpdate{}

	return u, nil
}

func (u *SelfUpdate) Run() (*semver.Version, error) {
	if !u.shouldCheck() {
		return nil, nil
	}
	version, err := u.doCheck()
	if err != nil {
		return nil, err
	}
	err = u.updateLastChecked()
	return version, err
}

func (u *SelfUpdate) shouldCheck() bool {
	config := GetConfig()
	now := time.Now().Unix()
	return config.LastUpdate == 0 || now-config.LastUpdate > int64(time.Hour*24)
}

func (u *SelfUpdate) updateLastChecked() error {
	config := GetConfig()
	config.LastUpdate = time.Now().Unix()
	config.Save()
	return nil
}

func (u *SelfUpdate) doCheck() (*semver.Version, error) {
	config := GetConfig()
	have := semver.MustParse(GetRootCmd().Version)
	wait := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	wait.Prefix = "Checking for latest version "
	_ = wait.Color("italic")
	wait.Start()
	defer wait.Stop()

	latest, found, err := selfupdate.DetectLatest(config.GithubUpdates)
	if err != nil {
		return nil, fmt.Errorf("error checking version: %v", err)
	} else if found && latest.Version.GT(have) {
		return &latest.Version, nil
	}
	return nil, nil
}
