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
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

type StatusCode int

const (
	NONE StatusCode = iota
	OK
	WARN
	ERR
)

type PrintOption int

const (
	ALL PrintOption = iota
	DetailsOnly
	DetailsOnErrorOrWarning
)

const okTemplate = "[ OK ] %s"
const warnTemplate = "[WARN] %s"
const errTemplate = "[ERR ] %s"

type Status interface {
	Code() StatusCode
	Message() string
}

type Summarizer interface {
	Summary() (string, error)
}

type Formatter interface {
	Format(indent string) string
}

type Report struct {
	Label      string
	StatusCode StatusCode
	Details    []Status
	Opt        PrintOption
	Data       []byte
	ReportSum  bool
}

func IsReport(s Status) bool {
	_, ok := s.(*Report)
	return ok
}

func ToReport(s Status) *Report {
	si, ok := s.(*Report)
	if ok {
		return si
	}
	return nil
}

func NewReport(code StatusCode, format string, args ...interface{}) *Report {
	return &Report{StatusCode: code, Label: fmt.Sprintf(format, args...)}
}

func NewDetailedReport(summary bool) *Report {
	return &Report{Opt: DetailsOnly, ReportSum: summary}
}

func FromError(err error) Status {
	return &Report{StatusCode: ERR, Label: err.Error()}
}

func OKStatus(format string, args ...interface{}) Status {
	return &Report{StatusCode: OK, Label: fmt.Sprintf(format, args...)}
}

func WarningStatus(format string, args ...interface{}) Status {
	return &Report{StatusCode: WARN, Label: fmt.Sprintf(format, args...)}
}

func ErrorStatus(format string, args ...interface{}) Status {
	return &Report{StatusCode: ERR, Label: fmt.Sprintf(format, args...)}
}

func (r *Report) AddStatus(code StatusCode, format string, args ...interface{}) *Report {
	c := NewReport(code, format, args...)
	r.Add(c)
	return c
}

func (r *Report) AddOK(format string, args ...interface{}) *Report {
	return r.AddStatus(OK, format, args...)
}

func (r *Report) AddWarning(format string, args ...interface{}) *Report {
	return r.AddStatus(WARN, format, args...)
}

func (r *Report) AddError(format string, args ...interface{}) *Report {
	return r.AddStatus(ERR, format, args...)
}

func (r *Report) AddFromError(err error) {
	r.Add(FromError(err))
}

func (r *Report) Add(status ...Status) {
	for _, s := range status {
		if s != nil {
			r.Details = append(r.Details, s)
		}
	}
	r.updateCode()
}

func (r *Report) Code() StatusCode {
	r.updateCode()
	return r.StatusCode
}

func (r *Report) OK() bool {
	r.updateCode()
	return r.StatusCode == OK
}

func (r *Report) HasErrors() bool {
	r.updateCode()
	return r.StatusCode == ERR
}

func (r *Report) HasNoErrors() bool {
	r.updateCode()
	return r.StatusCode != ERR
}

func (r *Report) updateCode() StatusCode {
	if len(r.Details) == 0 {
		return r.StatusCode
	}
	r.StatusCode = NONE
	for _, d := range r.Details {
		cc := d.Code()
		if cc > r.StatusCode {
			r.StatusCode = cc
		}
	}
	return r.StatusCode
}

func (r *Report) Message() string {
	r.updateCode()
	return r.Format("")
}

func (r *Report) printsSummary() bool {
	switch r.Opt {
	case ALL:
		return true
	case DetailsOnly:
		return false
	case DetailsOnErrorOrWarning:
		return true
	}
	return false
}

func (r *Report) printsDetails() bool {
	switch r.Opt {
	case ALL:
		return true
	case DetailsOnly:
		return true
	case DetailsOnErrorOrWarning:
		return r.StatusCode != OK || r.HasServerMessages()
	}
	return false
}

func (r *Report) HasServerMessages() bool {
	for _, v := range r.Details {
		if _, ok := v.(*ServerMessage); ok {
			return true
		}
	}
	return false
}

func (r *Report) Format(indent string) string {
	var buf bytes.Buffer
	var t string
	switch r.StatusCode {
	case NONE:
		return ""
	case OK:
		t = okTemplate
	case WARN:
		t = warnTemplate
	case ERR:
		t = errTemplate
	}
	if r.printsSummary() {
		m := fmt.Sprintf(t, r.Label)
		m = IndentMessage(m, indent)
		buf.WriteString(m)
		if len(r.Details) > 0 && r.printsDetails() {
			buf.WriteString(":\n")
			indent = fmt.Sprintf("%s       ", indent)
		}
	}
	if r.printsDetails() {
		for i, c := range r.Details {
			if i > 0 {
				buf.WriteRune('\n')
			}
			fm, ok := c.(Formatter)
			if ok {
				m := fm.Format(indent)
				buf.WriteString(m)
			} else {
				m := c.Message()
				m = IndentMessage(m, indent)
				buf.WriteString(m)
			}
		}
	}
	return buf.String()
}

func (r *Report) Summary() (string, error) {
	c := len(r.Details)
	var ok, warn, err int
	for _, j := range r.Details {
		switch j.Code() {
		case OK:
			ok++
		case WARN:
			warn++
		case ERR:
			err++
		}
	}

	ov := "job"
	if ok > 1 {
		ov = "jobs"
	}
	wv := "warnings"
	if warn > 1 {
		wv = "warnings"
	}
	ev := "job"
	if err > 1 {
		ev = "jobs"
	}

	// always return an error if we failed
	if err > 0 {
		m := "all jobs failed"
		if err != c {
			m = fmt.Sprintf("%d %s failed - %d %s succeeded and %d had %s", err, ev, ok, ov, warn, wv)
		}
		return "", errors.New(m)
	}
	if r.ReportSum {
		if ok == 1 && ok == c {
			// report says it worked
			return "", nil
		}
		if ok == c {
			return "all jobs succeeded", nil
		}
		if warn == 1 && warn == c {
			// report says it has a warning
			return "", nil
		}
		if warn == c {
			return "all jobs had warnings", nil
		}
		return fmt.Sprintf("%d %s succeeded - %d have %s", ok, ov, warn, wv), nil
	} else {
		return "", nil
	}
}

func HoistChildren(s Status) []Status {
	r, ok := s.(*Report)
	if !ok {
		return []Status{s}
	}
	if len(r.Details) == 0 {
		return []Status{s}
	}
	return r.Details
}

type ServerMessage struct {
	SrvMessage string
}

func NewServerMessage(format string, args ...interface{}) Status {
	m := fmt.Sprintf(format, args...)
	m = strings.TrimSpace(m)
	return &ServerMessage{SrvMessage: m}
}

func (s *ServerMessage) Code() StatusCode {
	return OK
}

func (s *ServerMessage) Message() string {
	return s.Format("> ")
}

func (s *ServerMessage) Format(prefix string) string {
	pf := fmt.Sprintf("%s> ", prefix)
	return IndentMessage(s.SrvMessage, pf)
}

func IndentMessage(s string, prefix string) string {
	lines := strings.Split(s, "\n")
	for i, v := range lines {
		vv := strings.TrimSpace(v)
		if vv == "" {
			continue
		}
		lines[i] = fmt.Sprintf("%s%s", prefix, v)
	}
	return strings.Join(lines, "\n")
}

func httpCodeToStatusCode(code int) StatusCode {
	switch code {
	case 0:
		return NONE
	case http.StatusOK:
		return OK
	case http.StatusCreated:
		fallthrough
	case http.StatusAccepted:
		return WARN
	default:
		return ERR
	}
}

func PushReport(code int, data []byte) Status {
	r := NewDetailedReport(true)
	r.Label = "push jwt to account server"
	r.Opt = DetailsOnErrorOrWarning
	sc := httpCodeToStatusCode(code)
	m := "failed to push account to remote server"
	switch sc {
	case OK:
		m = "pushed account jwt to the account server"
	case WARN:
		m = "pushed account jwt was accepted by the account server"
	}
	r.AddStatus(sc, m)
	if len(data) > 0 {
		r.Add(NewServerMessage(string(data)))
	}
	return r
}

func PullReport(code int, data []byte) Status {
	r := NewDetailedReport(true)
	r.Label = "pull jwt from account server"
	r.Opt = DetailsOnErrorOrWarning
	sc := httpCodeToStatusCode(code)
	m := fmt.Sprintf("failed to pull jwt from the account server: : [%d - %s]", code, http.StatusText(code))
	switch sc {
	case OK:
		m = "pulled jwt from the account server"
	default:
		// nothing - didn't get this far
	}
	r.AddStatus(sc, m)
	r.Data = data
	return r
}

type Statuses []Status

func (ms Statuses) Message() string {
	var buf bytes.Buffer
	for _, s := range ms {
		buf.WriteString(s.Message())
	}
	return buf.String()
}

type JobStatus struct {
	Warn string
	OK   string
	Err  error
}

func (js *JobStatus) Message() string {
	if js.Err != nil {
		return js.Err.Error()
	}
	if js.Warn != "" {
		return js.Warn
	}
	return js.OK
}

type MultiJob []Status

func (mj MultiJob) Code() StatusCode {
	code := NONE
	for _, j := range mj {
		c := j.Code()
		if c > code {
			code = c
		}
	}
	return code
}

func (mj MultiJob) Message() string {
	var buf bytes.Buffer
	for _, j := range mj {
		if buf.Len() > 0 {
			buf.WriteString("\n")
		}
		buf.WriteString(j.Message())
	}
	return buf.String()
}

func (mj MultiJob) Summary() (string, error) {
	c := len(mj)
	var ok, warn, err int
	for _, j := range mj {
		switch j.Code() {
		case OK:
			ok++
		case WARN:
			warn++
		case ERR:
			err++
		}
	}
	if ok == c {
		m := "all jobs succeeded"
		if c == 1 {
			m = "job succeeded"
		}
		return m, nil
	}
	if ok == 0 {
		m := "none of the jobs succeeded"
		if c == 1 {
			m = "job failed"
		}
		return "", errors.New(m)
	}
	if err > 0 {
		return "", fmt.Errorf("%d jobs failed - %d jobs succeeded and %d had warnings", err, ok, warn)
	}

	return fmt.Sprintf("%d jobs succeeded - there were %d errors and %d warnings", ok, err, warn), nil
}
