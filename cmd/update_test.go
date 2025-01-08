/*
 * Copyright 2018-2025 The NATS Authors
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
	"github.com/blang/semver"
	"github.com/rhysd/go-github-selfupdate/selfupdate"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

func TestUpdate_RunDoesntUpdateOrCheck(t *testing.T) {
	d := MakeTempDir(t)
	require.NoError(t, os.Setenv(NscHomeEnv, d))
	conf := GetConfig()
	conf.GithubUpdates = "foo/bar"
	conf.SetVersion("1.0.0")
	conf.LastUpdate = time.Now().Unix()

	var checkCalled bool
	var updateCalled bool
	updateCheckFn = func(slug string, wantVer string) (*selfupdate.Release, bool, error) {
		if wantVer != "" && !semver.MustParse(wantVer).EQ(semver.MustParse("1.0.0")) {
			return nil, false, fmt.Errorf("Expected request from 1.0.0 but got %s", wantVer)
		}
		checkCalled = true
		return &selfupdate.Release{Version: semver.MustParse("1.0.0"), ReleaseNotes: "f33dfac3"}, true, nil
	}
	updateFn = func(want *selfupdate.Release, cmdPath string) error {
		updateCalled = true
		return nil
	}
	defer func() {
		require.NoError(t, os.Unsetenv(NscHomeEnv))
		updateCheckFn = nil
		updateFn = nil
	}()

	su, err := NewSelfUpdate()
	require.NoError(t, err)
	require.NotNil(t, su)
	require.False(t, su.shouldCheck())
	_, err = su.Run()
	require.NoError(t, err)
	require.False(t, checkCalled)
	require.False(t, updateCalled)
}

func TestUpdate_NeedsUpdate(t *testing.T) {
	d := MakeTempDir(t)
	require.NoError(t, os.Setenv(NscHomeEnv, d))
	conf := GetConfig()
	conf.GithubUpdates = "foo/bar"
	conf.SetVersion("1.0.0")
	conf.LastUpdate = time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

	var checkCalled bool
	var updateCalled bool
	updateCheckFn = func(slug string, wantVer string) (*selfupdate.Release, bool, error) {
		if wantVer != "" && !semver.MustParse(wantVer).EQ(semver.MustParse("1.0.0")) {
			return nil, false, fmt.Errorf("Expected request from 1.0.0 but got %s", wantVer)
		}
		checkCalled = true
		return &selfupdate.Release{Version: semver.MustParse("1.0.1"), ReleaseNotes: "f33dfac3"}, true, nil
	}
	updateFn = func(want *selfupdate.Release, cmdPath string) error {
		updateCalled = true
		return nil
	}
	defer func() {
		require.NoError(t, os.Unsetenv(NscHomeEnv))
		updateCheckFn = nil
		updateFn = nil
	}()

	su, err := NewSelfUpdate()
	require.NoError(t, err)
	require.NotNil(t, su)
	require.True(t, su.shouldCheck()) // prevents updateFn from bein called
	_, err = su.Run()
	require.NoError(t, err)
	require.True(t, checkCalled)
	require.False(t, updateCalled)
}

func TestUpdate_DoUpdateWithV(t *testing.T) {
	d := MakeTempDir(t)
	require.NoError(t, os.Setenv(NscHomeEnv, d))
	conf := GetConfig()
	conf.GithubUpdates = "foo/bar"
	conf.SetVersion("v1.0.0")
	conf.LastUpdate = time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

	var checkCalled bool
	var updateCalled bool
	updateCheckFn = func(slug string, wantVer string) (*selfupdate.Release, bool, error) {
		if wantVer != "" && !semver.MustParse(wantVer).EQ(semver.MustParse("1.0.0")) {
			return nil, false, fmt.Errorf("expected request from 1.0.0 but got %s", wantVer)
		}
		checkCalled = true
		return &selfupdate.Release{Version: semver.MustParse("1.0.1"), ReleaseNotes: "f33dfac3"}, true, nil
	}
	updateFn = func(want *selfupdate.Release, cmdPath string) error {
		updateCalled = true
		return nil
	}
	defer func() {
		require.NoError(t, os.Unsetenv(NscHomeEnv))
		updateCheckFn = nil
		updateFn = nil
	}()

	out, err := ExecuteCmd(createUpdateCommand())
	require.NoError(t, err)
	require.True(t, checkCalled)
	require.True(t, updateCalled)
	require.Contains(t, out.Out, "f33dfac3")
}

func TestUpdate_DoUpdate(t *testing.T) {
	d := MakeTempDir(t)
	require.NoError(t, os.Setenv(NscHomeEnv, d))
	conf := GetConfig()
	conf.GithubUpdates = "foo/bar"
	conf.SetVersion("1.0.0")
	conf.LastUpdate = time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

	var checkCalled bool
	var updateCalled bool
	updateCheckFn = func(slug string, wantVer string) (*selfupdate.Release, bool, error) {
		if wantVer != "" && !semver.MustParse(wantVer).EQ(semver.MustParse("1.0.0")) {
			return nil, false, fmt.Errorf("expected request from 1.0.0 but got %s", wantVer)
		}
		checkCalled = true
		return &selfupdate.Release{Version: semver.MustParse("1.0.1"), ReleaseNotes: "f33dfac3"}, true, nil
	}
	updateFn = func(want *selfupdate.Release, cmdPath string) error {
		updateCalled = true
		return nil
	}
	defer func() {
		require.NoError(t, os.Unsetenv(NscHomeEnv))
		updateCheckFn = nil
		updateFn = nil
	}()

	out, err := ExecuteCmd(createUpdateCommand())
	require.NoError(t, err)
	require.True(t, checkCalled)
	require.True(t, updateCalled)
	require.Contains(t, out.Out, "f33dfac3")
}

func TestUpdate_VerPresent(t *testing.T) {
	d := MakeTempDir(t)
	require.NoError(t, os.Setenv(NscHomeEnv, d))
	conf := GetConfig()
	conf.GithubUpdates = "foo/bar"
	conf.SetVersion("v1.0.0")
	conf.LastUpdate = time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

	var checkCalled bool
	var updateCalled bool
	updateCheckFn = func(slug string, wantVer string) (*selfupdate.Release, bool, error) {
		if !semver.MustParse(wantVer).EQ(semver.MustParse("2.0.0")) {
			return nil, false, fmt.Errorf("expected request from 2.0.0 but got %s", wantVer)
		}
		checkCalled = true
		return &selfupdate.Release{Version: semver.MustParse("2.0.0"), ReleaseNotes: "f33dfac3"}, true, nil
	}
	updateFn = func(want *selfupdate.Release, cmdPath string) error {
		updateCalled = true
		return nil
	}
	defer func() {
		require.NoError(t, os.Unsetenv(NscHomeEnv))
		updateCheckFn = nil
		updateFn = nil
	}()

	out, err := ExecuteCmd(createUpdateCommand(), "--version", "2.0.0")
	require.NoError(t, err)
	require.True(t, checkCalled)
	require.True(t, updateCalled)
	require.Contains(t, out.Out, "f33dfac3")
}

func TestUpdate_VerSame(t *testing.T) {
	d := MakeTempDir(t)
	require.NoError(t, os.Setenv(NscHomeEnv, d))
	conf := GetConfig()
	conf.GithubUpdates = "foo/bar"
	conf.SetVersion("v1.0.0")
	conf.LastUpdate = time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

	var checkCalled bool
	var updateCalled bool
	updateCheckFn = func(slug string, wantVer string) (*selfupdate.Release, bool, error) {
		if !semver.MustParse(wantVer).EQ(semver.MustParse("1.0.0")) {
			return nil, false, fmt.Errorf("Expected request from 2.0.0 but got %s", wantVer)
		}
		checkCalled = true
		return &selfupdate.Release{Version: semver.MustParse("1.0.0"), ReleaseNotes: "f33dfac3"}, true, nil
	}
	updateFn = func(want *selfupdate.Release, cmdPath string) error {
		updateCalled = true
		return nil
	}
	defer func() {
		require.NoError(t, os.Unsetenv(NscHomeEnv))
		updateCheckFn = nil
		updateFn = nil
	}()

	_, err := ExecuteCmd(createUpdateCommand(), []string{"--version", "1.0.0"}...)
	require.NoError(t, err)
	require.True(t, checkCalled)
	require.False(t, updateCalled)
}

func TestUpdate_VerNotFound(t *testing.T) {
	d := MakeTempDir(t)
	require.NoError(t, os.Setenv(NscHomeEnv, d))
	conf := GetConfig()
	conf.GithubUpdates = "foo/bar"
	conf.SetVersion("v1.0.0")
	conf.LastUpdate = time.Date(2018, 1, 1, 0, 0, 0, 0, time.UTC).Unix()

	var checkCalled bool
	var updateCalled bool
	updateCheckFn = func(slug string, wantVer string) (*selfupdate.Release, bool, error) {
		if !semver.MustParse(wantVer).EQ(semver.MustParse("2.0.0")) {
			return nil, false, fmt.Errorf("Expected request from 2.0.0 but got %s", wantVer)
		}
		checkCalled = true
		return nil, false, nil
	}
	updateFn = func(want *selfupdate.Release, cmdPath string) error {
		updateCalled = true
		return nil
	}
	defer func() {
		require.NoError(t, os.Unsetenv(NscHomeEnv))
		updateCheckFn = nil
		updateFn = nil
	}()

	out, err := ExecuteCmd(createUpdateCommand(), []string{"--version", "2.0.0"}...)
	require.Error(t, err)
	require.True(t, checkCalled)
	require.False(t, updateCalled)
	require.Contains(t, out.Err, "version 2.0.0 not found")
}
