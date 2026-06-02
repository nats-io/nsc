// Copyright 2019 The NATS Authors
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
	require.Len(t, lines, 4)
	require.Contains(t, lines[0], fmt.Sprintf(errTemplate, "main"))
	require.Contains(t, lines[1], fmt.Sprintf(okTemplate, "A"))
	require.Contains(t, lines[2], fmt.Sprintf(errTemplate, "B"))
	require.Contains(t, lines[3], fmt.Sprintf(warnTemplate, "C"))
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

func Test_StatusPromotesError(t *testing.T) {
	s := NewReport(NONE, "main")
	s.Opt = DetailsOnly
	s.Details = append(s.Details, OKStatus("A"), ErrorStatus("B"), WarningStatus("C"))
	require.True(t, s.HasErrors())

	t.Log(s.Message())
}

func Test_Nested(t *testing.T) {
	s := NewReport(NONE, "main")
	s.Opt = DetailsOnly
	a := NewReport(OK, "A")
	a.Opt = DetailsOnErrorOrWarning
	a.AddOK("something ok")
	s.Add(a)

	b := NewReport(OK, "B")
	b.Opt = DetailsOnErrorOrWarning
	b.AddOK("something ok")
	b.AddWarning("something not so great")
	b.AddError("some error")
	s.Add(b)

	m := s.Message()
	lines := strings.Split(m, "\n")
	require.Len(t, lines, 5)
	require.Contains(t, lines[0], fmt.Sprintf(okTemplate, "A"))
	require.Contains(t, lines[1], fmt.Sprintf(errTemplate, "B"))
	require.Contains(t, lines[2], fmt.Sprintf(okTemplate, "something ok"))
	require.Contains(t, lines[3], fmt.Sprintf(warnTemplate, "something not so great"))
	require.Contains(t, lines[4], fmt.Sprintf(errTemplate, "some error"))
}

func Test_Report_OK_HasNoErrors(t *testing.T) {
	r := NewSimpleReport(OK, "main")
	require.True(t, r.OK())
	require.True(t, r.HasNoErrors())
	require.False(t, r.HasErrors())

	r.AddWarning("careful")
	require.False(t, r.OK())
	require.True(t, r.HasNoErrors())

	r.AddError("boom")
	require.False(t, r.OK())
	require.False(t, r.HasNoErrors())
	require.True(t, r.HasErrors())
}

func Test_ServerMessage_Message(t *testing.T) {
	sm := NewSimpleServerMessage("hello\nworld")
	m := sm.Message()
	// Message prefixes each non-empty line
	lines := strings.Split(m, "\n")
	require.Equal(t, "> > hello", lines[0])
	require.Equal(t, "> > world", lines[1])
	require.Equal(t, OK, sm.Code())
}

func Test_IsReport_ToReport(t *testing.T) {
	r := NewSimpleReport(OK, "hi")
	require.True(t, IsReport(r))
	require.Same(t, r, ToReport(r))

	sm := NewServerMessage("plain")
	require.False(t, IsReport(sm))
	require.Nil(t, ToReport(sm))
}

func Test_NewDetailedReport(t *testing.T) {
	r := NewDetailedReport(true)
	require.Equal(t, DetailsOnly, r.Opt)
	require.True(t, r.ReportSum)

	r2 := NewDetailedReport(false)
	require.False(t, r2.ReportSum)
}

func Test_AddSimpleStatus(t *testing.T) {
	r := NewSimpleReport(NONE, "main")
	c := r.AddSimpleStatus(WARN, "careful")
	require.Equal(t, WARN, c.StatusCode)
	require.Equal(t, "careful", c.Label)
	require.Equal(t, WARN, r.Code())
	require.Len(t, r.Details, 1)
}

func Test_AddFromError(t *testing.T) {
	r := NewSimpleReport(NONE, "main")
	r.AddFromError(errors.New("boom"))
	require.Equal(t, ERR, r.Code())
	require.Len(t, r.Details, 1)
	require.Contains(t, r.Message(), "boom")
}

func Test_ReportSummary_AllOK(t *testing.T) {
	r := NewDetailedReport(true)
	r.AddOK("a")
	r.AddOK("b")
	msg, err := r.Summary()
	require.NoError(t, err)
	require.Equal(t, "all jobs succeeded", msg)
}

func Test_ReportSummary_SingleOK_NoMessage(t *testing.T) {
	r := NewDetailedReport(true)
	r.AddOK("only")
	msg, err := r.Summary()
	require.NoError(t, err)
	require.Equal(t, "", msg)
}

func Test_ReportSummary_AllErr(t *testing.T) {
	r := NewDetailedReport(true)
	r.AddError("a")
	r.AddError("b")
	_, err := r.Summary()
	require.Error(t, err)
	require.Equal(t, "all jobs failed", err.Error())
}

func Test_ReportSummary_MixedErr(t *testing.T) {
	r := NewDetailedReport(true)
	r.AddOK("a")
	r.AddWarning("b")
	r.AddError("c")
	_, err := r.Summary()
	require.Error(t, err)
	// when not all jobs failed, error contains counts
	require.Contains(t, err.Error(), "1")
	require.Contains(t, err.Error(), "failed")
}

func Test_ReportSummary_MixedOKWarn(t *testing.T) {
	r := NewDetailedReport(true)
	r.AddOK("a")
	r.AddOK("b")
	r.AddWarning("c")
	msg, err := r.Summary()
	require.NoError(t, err)
	require.Contains(t, msg, "succeeded")
	require.Contains(t, msg, "warnings")
}

func Test_ReportSummary_ReportSumOff(t *testing.T) {
	r := NewSimpleReport(NONE, "main") // ReportSum defaults to false
	r.AddOK("a")
	msg, err := r.Summary()
	require.NoError(t, err)
	require.Equal(t, "", msg)
}

func Test_MultiJob_Code(t *testing.T) {
	mj := MultiJob{OKStatus("a"), WarningStatus("b")}
	require.Equal(t, WARN, mj.Code())

	mj = MultiJob{OKStatus("a"), ErrorStatus("b"), WarningStatus("c")}
	require.Equal(t, ERR, mj.Code())
}

func Test_MultiJob_Message(t *testing.T) {
	mj := MultiJob{OKStatus("a"), WarningStatus("b")}
	m := mj.Message()
	lines := strings.Split(m, "\n")
	require.Len(t, lines, 2)
	require.Contains(t, lines[0], "a")
	require.Contains(t, lines[1], "b")
}

func Test_MultiJob_Summary_AllOK(t *testing.T) {
	mj := MultiJob{OKStatus("a"), OKStatus("b")}
	msg, err := mj.Summary()
	require.NoError(t, err)
	require.Equal(t, "all jobs succeeded", msg)
}

func Test_MultiJob_Summary_SingleOK(t *testing.T) {
	mj := MultiJob{OKStatus("a")}
	msg, err := mj.Summary()
	require.NoError(t, err)
	require.Equal(t, "job succeeded", msg)
}

func Test_MultiJob_Summary_AllFailed(t *testing.T) {
	mj := MultiJob{ErrorStatus("a"), ErrorStatus("b")}
	_, err := mj.Summary()
	require.Error(t, err)
	require.Equal(t, "none of the jobs succeeded", err.Error())
}

func Test_MultiJob_Summary_SingleFailed(t *testing.T) {
	mj := MultiJob{ErrorStatus("a")}
	_, err := mj.Summary()
	require.Error(t, err)
	require.Equal(t, "job failed", err.Error())
}

func Test_MultiJob_Summary_MixedWithErrors(t *testing.T) {
	mj := MultiJob{OKStatus("a"), ErrorStatus("b"), WarningStatus("c")}
	_, err := mj.Summary()
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed")
}

func Test_MultiJob_Summary_OKAndWarn(t *testing.T) {
	mj := MultiJob{OKStatus("a"), OKStatus("b"), WarningStatus("c")}
	msg, err := mj.Summary()
	require.NoError(t, err)
	require.Contains(t, msg, "succeeded")
	require.Contains(t, msg, "warnings")
}

func Test_PushReport_Codes(t *testing.T) {
	cases := []struct {
		code int
		want StatusCode
		body string
	}{
		{http.StatusOK, OK, "pushed account jwt to the account server"},
		{http.StatusCreated, WARN, "accepted by the account server"},
		{http.StatusBadRequest, ERR, "failed to push"},
	}
	for _, c := range cases {
		r := PushReport(c.code, nil)
		report := ToReport(r)
		require.NotNil(t, report, "code %d", c.code)
		require.Equal(t, c.want, report.Code(), "code %d", c.code)
		// the per-code detail text lives on the child status
		require.Len(t, report.Details, 1, "code %d", c.code)
		require.Contains(t, report.Details[0].Message(), c.body, "code %d", c.code)
	}

	// server data is attached as a server message and surfaces in the message
	r := PushReport(http.StatusOK, []byte("hello from server"))
	require.Contains(t, r.Message(), "hello from server")
}

func Test_PullReport_Codes(t *testing.T) {
	r := PullReport(http.StatusOK, []byte("jwt-bytes"))
	report := ToReport(r)
	require.NotNil(t, report)
	require.Equal(t, OK, report.Code())
	require.Equal(t, []byte("jwt-bytes"), report.Data)

	// non-OK preserves status data and surfaces a failure message
	r = PullReport(http.StatusNotFound, []byte("missing"))
	report = ToReport(r)
	require.NotNil(t, report)
	require.Equal(t, ERR, report.Code())
	require.Equal(t, []byte("missing"), report.Data)
	require.Contains(t, report.Message(), "failed to pull")
}

func Test_HoistChildren(t *testing.T) {
	// non-report status is returned unchanged
	sm := NewSimpleServerMessage("plain")
	out := HoistChildren(sm)
	require.Len(t, out, 1)
	require.Same(t, sm, out[0])

	// report with no children returns the report
	r := NewSimpleReport(OK, "alone")
	out = HoistChildren(r)
	require.Len(t, out, 1)

	// report with children returns the children
	r = NewSimpleReport(NONE, "parent")
	a := OKStatus("a")
	b := WarningStatus("b")
	r.Add(a, b)
	out = HoistChildren(r)
	require.Len(t, out, 2)
}

func Test_JobStatus_Message(t *testing.T) {
	js := &JobStatus{OK: "ok-text"}
	require.Equal(t, "ok-text", js.Message())

	js = &JobStatus{Warn: "warn-text"}
	require.Equal(t, "warn-text", js.Message())

	js = &JobStatus{Err: errors.New("err-text")}
	require.Equal(t, "err-text", js.Message())

	// err wins over warn/ok
	js = &JobStatus{OK: "o", Warn: "w", Err: errors.New("e")}
	require.Equal(t, "e", js.Message())
}

func Test_IndentMessage(t *testing.T) {
	in := "line1\n\nline2\n   line3"
	got := IndentMessage(in, ">>")
	lines := strings.Split(got, "\n")
	require.Equal(t, ">>line1", lines[0])
	require.Equal(t, "", lines[1]) // blank line is preserved as blank, no prefix
	require.Equal(t, ">>line2", lines[2])
	require.Equal(t, ">>   line3", lines[3])
}

func Test_NewServerMessage_Trims(t *testing.T) {
	sm := NewServerMessage("  hello %s  ", "world")
	got := sm.(*ServerMessage).SrvMessage
	require.Equal(t, "hello world", got)
}

func Test_Statuses_Message(t *testing.T) {
	ss := Statuses{OKStatus("a"), WarningStatus("b")}
	m := ss.Message()
	// Statuses.Message concatenates without separators
	require.Contains(t, m, "a")
	require.Contains(t, m, "b")
}

func Test_Report_AddNil_Skipped(t *testing.T) {
	r := NewSimpleReport(OK, "main")
	var nilReport *Report
	r.Add(nilReport)
	// nil typed report should be skipped
	require.Empty(t, r.Details)
}

func Test_ServerMessagesAlwaysShow(t *testing.T) {
	s := NewReport(OK, "summary")
	s.Opt = DetailsOnErrorOrWarning
	s.AddOK("one")

	m := s.Message()
	lines := strings.Split(m, "\n")
	require.Len(t, lines, 1)
	require.Contains(t, lines[0], "summary")

	s.Add(NewServerMessage("server says"))
	m = s.Message()
	lines = strings.Split(m, "\n")
	require.Len(t, lines, 3)
	require.Contains(t, lines[0], "summary")
	require.Contains(t, lines[1], "one")
	require.Contains(t, lines[2], "server says")
}
