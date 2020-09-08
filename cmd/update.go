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
	"strings"
	"time"

	"github.com/blang/semver"

	"github.com/briandowns/spinner"
	cli "github.com/nats-io/cliprompts/v2"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
	"github.com/spf13/cobra"
)

type semV string

func (r *semV) String() string {
	if *r == "" {
		return "latest"
	}
	return string(*r)
}

func (r *semV) Type() string {
	return "version"
}

func (r *semV) Set(s string) error {
	if strings.ToLower(strings.TrimSpace(s)) == "latest" {
		*r = ""
	} else if v, err := semver.ParseTolerant(s); err != nil {
		return err
	} else {
		*r = semV(v.String())
	}
	return nil
}

func createUpdateCommand() *cobra.Command {
	ver := semV("")
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
			cmdPath, err := os.Executable()
			if err != nil {
				return err
			}
			su, err := NewSelfUpdate()
			if err != nil {
				return err
			}
			nvs, err := su.doCheck(string(ver))
			if err != nil {
				return err
			}
			if nvs == nil {
				cmd.Println("Current version", v, "is requested version")
				return nil
			}

			wait := spinner.New(spinner.CharSets[14], 250*time.Millisecond)
			defer wait.Stop()

			wait.Prefix = fmt.Sprintf("Downloading version: %s", ver.String())
			_ = wait.Color("italic")
			wait.Start()

			if updateFn == nil {
				// the library freak out if GITHUB_TOKEN is set - don't break travis :)
				_ = os.Setenv("GITHUB_TOKEN", "")

				err = selfupdate.DefaultUpdater().UpdateTo(nvs, cmdPath)
			} else {
				err = updateFn(nvs, cmdPath)
			}
			if err != nil {
				cmd.SilenceErrors = false
				return err
			}

			cmd.Printf("Successfully updated to version %s\n", nvs.Version.String())
			cmd.Println()
			cmd.Println("Release Notes:")
			cmd.Println()
			cmd.Println(cli.Wrap(80, nvs.ReleaseNotes))

			return nil
		},
	}
	cmd.Flags().Var(&ver, "version", "version to updated the nsc binary to")
	return cmd
}

func init() {
	GetRootCmd().AddCommand(createUpdateCommand())
}

type UpdateCheckFn func(slug string, wantVer string) (*selfupdate.Release, bool, error)
type UpdateFn func(want *selfupdate.Release, cmdPath string) error

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
	rel, err := u.doCheck("")
	if err != nil {
		// stop checking for a bit
		_ = u.updateLastChecked()
		return nil, err
	}
	err = u.updateLastChecked()
	if rel == nil {
		return nil, err
	} else {
		return &rel.Version, err
	}
}

func (u *SelfUpdate) shouldCheck() bool {
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

func (u *SelfUpdate) doCheck(wantVer string) (*selfupdate.Release, error) {
	config := GetConfig()
	have, err := semver.ParseTolerant(GetRootCmd().Version)
	if err != nil {
		return nil, err
	}
	if wantVer != "" {
		want, err := semver.ParseTolerant(wantVer)
		if err != nil {
			return nil, err
		}
		wantVer = want.String()
	}
	wait := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	if wantVer == "" {
		wait.Prefix = "Checking for latest version "
	} else {
		wait.Prefix = fmt.Sprintf("Checking for version %s ", wantVer)
	}
	_ = wait.Color("italic")
	wait.Start()
	defer wait.Stop()

	var want *selfupdate.Release
	var found bool
	if updateCheckFn == nil {
		// the library freak out if GITHUB_TOKEN is set - don't break travis :)
		_ = os.Setenv("GITHUB_TOKEN", "")
		if wantVer == "" {
			want, found, err = selfupdate.DetectLatest(config.GithubUpdates)
		} else {
			want, found, err = selfupdate.DetectVersion(GetConfig().GithubUpdates, wantVer)
		}
	} else {
		want, found, err = updateCheckFn(config.GithubUpdates, wantVer)
	}
	if err != nil {
		return nil, fmt.Errorf("error checking version: %v", err)
	} else if !found {
		return nil, fmt.Errorf("version %v not found", wantVer)
	} else if !want.Version.EQ(have) {
		return want, nil
	}
	return nil, nil
}
