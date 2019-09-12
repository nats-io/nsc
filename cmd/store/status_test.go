/*
 * Copyright 2019 The NATS Authors
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

package store

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_ReportFormatNone(t *testing.T) {
	var s Report
	s.StatusCode = NONE
	require.Equal(t, "", s.Message())
}

func Test_ReportFormatOK(t *testing.T) {
	s := OKStatus("testing")
	require.Equal(t, fmt.Sprintf(okTemplate, "testing"), s.Message())
}

func TestReportVarargs(t *testing.T) {
	s := OKStatus("testing %s", "args")
	require.Equal(t, fmt.Sprintf(okTemplate, "testing args"), s.Message())
}

func Test_ReportFormatErr(t *testing.T) {
	s := ErrorStatus("testing")
	require.Equal(t, fmt.Sprintf(errTemplate, "testing"), s.Message())
}

func Test_ErrReport(t *testing.T) {
	s := FromError(errors.New("testing"))
	require.Equal(t, fmt.Sprintf(errTemplate, "testing"), s.Message())
}

func Test_ReportFormatWarn(t *testing.T) {
	s := WarningStatus("testing")
	require.Equal(t, fmt.Sprintf(warnTemplate, "testing"), s.Message())
}

func Test_ReportChildren(t *testing.T) {
	s := NewReport(NONE, "main")
	s.Details = append(s.Details, OKStatus("A"), ErrorStatus("B"), WarningStatus("C"))

	m := s.Message()
	lines := strings.Split(m, "\n")
	require.Len(t, lines, 4)
	require.Contains(t, lines[0], fmt.Sprintf(errTemplate, "main:"))
	require.Contains(t, lines[1], fmt.Sprintf(okTemplate, "A"))
	require.Contains(t, lines[2], fmt.Sprintf(errTemplate, "B"))
	require.Contains(t, lines[3], fmt.Sprintf(warnTemplate, "C"))
}

func Test_ReportChildrenOnly(t *testing.T) {
	s := NewReport(NONE, "main")
	s.Opt = DetailsOnly
	s.Details = append(s.Details, OKStatus("A"), ErrorStatus("B"), WarningStatus("C"))

	m := s.Message()
	lines := strings.Split(m, "\n")
	require.Len(t, lines, 3)
	require.Contains(t, lines[0], fmt.Sprintf(okTemplate, "A"))
	require.Contains(t, lines[1], fmt.Sprintf(errTemplate, "B"))
	require.Contains(t, lines[2], fmt.Sprintf(warnTemplate, "C"))
}

func Test_ReportChildrenOnError(t *testing.T) {
	s := NewReport(NONE, "main")
	s.Opt = DetailsOnErrorOrWarning
	s.Details = append(s.Details, OKStatus("A"), ErrorStatus("B"), WarningStatus("C"))

	m := s.Message()
	t.Log(m)
	lines := strings.Split(m, "\n")
	require.Len(t, lines, 3)
	require.Contains(t, lines[0], fmt.Sprintf(okTemplate, "A"))
	require.Contains(t, lines[1], fmt.Sprintf(errTemplate, "B"))
	require.Contains(t, lines[2], fmt.Sprintf(warnTemplate, "C"))
}

func Test_ReportNoChildrenOnOK(t *testing.T) {
	s := NewReport(NONE, "main")
	s.Opt = DetailsOnErrorOrWarning
	s.Details = append(s.Details, OKStatus("A"), OKStatus("B"), OKStatus("C"))

	m := s.Message()
	t.Log(m)
	lines := strings.Split(m, "\n")
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], fmt.Sprintf(okTemplate, "main"))
}

func TestHttpCodeConversion(t *testing.T) {
	ct := []struct {
		in  int
		out StatusCode
	}{
		{0, NONE},
		{1, ERR},
		{http.StatusOK, OK},
		{http.StatusCreated, WARN},
		{http.StatusAccepted, WARN},
		{http.StatusBadRequest, ERR},
	}

	for _, c := range ct {
		out := httpCodeToStatusCode(c.in)
		require.Equal(t, c.out, out, "test %v failed", c)
	}
}
