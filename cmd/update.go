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
	"fmt"
	"os"
	"time"

	"github.com/blang/semver"
	"github.com/briandowns/spinner"
	cli "github.com/nats-io/cliprompts/v2"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
	"github.com/spf13/cobra"
)

func createUpdateCommand() *cobra.Command {
	var cmd = &cobra.Command{
		Example: "nsc update",
		Use:     "update",
		Short:   "Update this tool to latest version",
		Args:    MaxArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := semver.ParseTolerant(GetRootCmd().Version)
			if err != nil {
				return err
			}

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

			wait := spinner.New(spinner.CharSets[14], 250*time.Millisecond)
			defer wait.Stop()

			wait.Prefix = "Downloading latest version "
			_ = wait.Color("italic")
			wait.Start()

			var latest *selfupdate.Release
			if updateFn == nil {
				// the library freak out if GITHUB_TOKEN is set - don't break travis :)
				_ = os.Setenv("GITHUB_TOKEN", "")
				latest, err = selfupdate.UpdateSelf(v, GetConfig().GithubUpdates)
			} else {
				latest, err = updateFn(v, GetConfig().GithubUpdates)
			}
			if err != nil {
				cmd.SilenceErrors = false
				return err
			}

			cmd.Printf("Successfully updated to version %s\n", latest.Version.String())
			cmd.Println()
			cmd.Println("Release Notes:")
			cmd.Println()
			cmd.Println(cli.Wrap(80, latest.ReleaseNotes))

			return nil
		},
	}

	return cmd
}

func init() {
	GetRootCmd().AddCommand(createUpdateCommand())
}

type UpdateCheckFn func(slug string) (*selfupdate.Release, bool, error)
type UpdateFn func(current semver.Version, slug string) (*selfupdate.Release, error)

var updateCheckFn UpdateCheckFn
var updateFn UpdateFn

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
		// stop checking for a bit
		_ = u.updateLastChecked()
		return nil, err
	}
	err = u.updateLastChecked()
	return version, err
}

func (u *SelfUpdate) shouldCheck() bool {
	if NscNoSelfUpdate {
		return false
	}
	have := semver.MustParse(GetRootCmd().Version).String()
	if have == "0.0.0-dev" {
		return false
	}
	config := GetConfig()
	now := time.Now().Unix()
	diff := now - config.LastUpdate

	return config.LastUpdate == 0 || diff > int64(60*60*24)
}

func (u *SelfUpdate) updateLastChecked() error {
	config := GetConfig()
	config.LastUpdate = time.Now().Unix()
	return config.Save()
}

func (u *SelfUpdate) doCheck() (*semver.Version, error) {
	config := GetConfig()
	have, err := semver.ParseTolerant(GetRootCmd().Version)
	if err != nil {
		return nil, err
	}
	wait := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	wait.Prefix = "Checking for latest version "
	_ = wait.Color("italic")
	wait.Start()
	defer wait.Stop()

	var latest *selfupdate.Release
	var found bool
	if updateCheckFn == nil {
		// the library freak out if GITHUB_TOKEN is set - don't break travis :)
		_ = os.Setenv("GITHUB_TOKEN", "")
		latest, found, err = selfupdate.DetectLatest(config.GithubUpdates)
	} else {
		latest, found, err = updateCheckFn(config.GithubUpdates)
	}
	if err != nil {
		return nil, fmt.Errorf("error checking version: %v", err)
	} else if found && latest.Version.GT(have) {
		return &latest.Version, nil
	}
	return nil, nil
}
