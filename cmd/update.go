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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/blang/semver"
	"github.com/briandowns/spinner"
	"github.com/mitchellh/go-homedir"
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
			latest, err := selfupdate.UpdateSelf(v, repository)
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

var repository string

func SetUpdateRespository(githubrepo string) {
	repository = githubrepo
}

type SelfUpdate struct {
	LastCheck int64 `json:"last_check"`
}

// NewSelfUpdate
func NewSelfUpdate() (*SelfUpdate, error) {
	if repository == "" {
		return nil, fmt.Errorf("unable to check for updates - repository not set")
	}

	var u SelfUpdate
	fn, err := u.infoFile()
	d, err := ioutil.ReadFile(fn)
	if err != nil && os.IsNotExist(err) {
		// go check
	} else if err != nil {
		return nil, fmt.Errorf("error checking self update: %v", err.Error())
	} else {
		if err := json.Unmarshal(d, &u); err != nil {
			return nil, fmt.Errorf("error reading %q: %v", fn, err.Error())
		}
	}
	return &u, nil
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
	now := time.Now().Unix()
	return u.LastCheck == 0 || now-u.LastCheck > int64(time.Hour*24)
}

func (u *SelfUpdate) updateLastChecked() error {
	u.LastCheck = time.Now().Unix()
	d, err := json.Marshal(u)
	if err != nil {
		return fmt.Errorf("error serialzing selfupdate info: %v", err)
	}
	fp, err := u.infoFile()
	if err != nil {
		return fmt.Errorf("error getting path for selfupdate info file: %v", err)
	}
	dir := filepath.Dir(fp)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("error creating dir %q: %v", dir, err)

	}
	if err := ioutil.WriteFile(fp, d, 0600); err != nil {
		return fmt.Errorf("error writing %q: %v", fp, err)
	}
	return nil
}

func (u *SelfUpdate) infoFile() (string, error) {
	dir, err := homedir.Dir()
	if err != nil {
		// shouldn't prevent if there's an error
		return "", fmt.Errorf("error getting homedir: %v", err.Error())
	}
	exeName := filepath.Base(os.Args[0])
	fn := filepath.Join(dir, fmt.Sprintf(".%scli/%s.ini", exeName, exeName))
	return fn, nil
}

func (u *SelfUpdate) doCheck() (*semver.Version, error) {
	have := semver.MustParse(GetRootCmd().Version)
	wait := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	wait.Prefix = "Checking for latest version "
	_ = wait.Color("italic")
	wait.Start()
	defer wait.Stop()

	latest, found, err := selfupdate.DetectLatest(repository)
	if err != nil {
		return nil, fmt.Errorf("error checking version: %v", err)
	} else if found && latest.Version.GT(have) {
		return &latest.Version, nil
	}
	return nil, nil
}
