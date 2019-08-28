/*
 * Copyright 2018-2019 The NATS Authors
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
)

type Status interface {
	Message() string
}

type HttpStatus struct {
	Status int
}

func (s *HttpStatus) OK() bool {
	return s.Status == http.StatusOK
}

func (s *HttpStatus) Pending() bool {
	return s.Status == http.StatusAccepted
}

type PushStatus struct {
	HttpStatus
	OperatorMessage []byte
}

func (ps *PushStatus) Message() string {
	buf := bytes.NewBufferString("")

	hasPushMessage := len(ps.OperatorMessage) > 0
	switch ps.Status {
	case http.StatusOK:
		buf.WriteString("Successfully pushed the account configuration to the remote server.\n")
		if hasPushMessage {
			buf.WriteString("Please review the following operator message:\n")
			buf.Write(ps.OperatorMessage)
			buf.WriteString("\n")
		}

	case http.StatusAccepted:
		buf.WriteString("The account configuration was accepted by the remote server.\n")
		if hasPushMessage {
			buf.WriteString("Please review the following operator message, as it may contain additional information\n")
			buf.WriteString("required to finalize your account setup:\n")
			buf.Write(ps.OperatorMessage)
			buf.WriteString("\n")
		}
	default:
		buf.WriteString("Failed to push the account to the remote server.\n")
		if hasPushMessage {
			buf.WriteString("Please review the following operator message for additional information:\n")
			buf.Write(ps.OperatorMessage)
			buf.WriteString("\n")
		}
	}
	return buf.String()
}

type PullStatus struct {
	HttpStatus
	Data []byte
}

func (ps *PullStatus) Message() string {
	buf := bytes.NewBufferString("")

	switch ps.Status {
	case http.StatusOK:
		buf.WriteString("The account configuration was successfully pulled from the operator.\n")
		buf.WriteString("The operator may have set some limits or added imports to your account.\n")
		buf.WriteString("Please enter nsc describe account to review your account configuration.\n")
	default:
		buf.WriteString(fmt.Sprintf("Failed to pull the account configuration from the operator: [%d - %s].\n",
			ps.Status, http.StatusText(ps.Status)))
	}

	return buf.String()
}

type PushPullStatus struct {
	Push PushStatus
	Pull PullStatus
}

func (r *PushPullStatus) Message() string {
	buf := bytes.NewBufferString("")

	pushMsg := r.Push.Message()
	if pushMsg != "" {
		buf.WriteString(pushMsg)
	}

	pullMsg := r.Pull.Message()
	if pullMsg != "" {
		buf.WriteString(pullMsg)
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

type MultiJob []JobStatus

func (mj MultiJob) Message() string {
	ok := "[ OK ] "
	warn := "[WARN] "
	err := "[ERR ] "
	var buf bytes.Buffer
	for _, j := range mj {
		if buf.Len() > 0 {
			buf.WriteString("\n")
		}
		if j.Err != nil {
			buf.WriteString(err)
		} else if j.Warn != "" {
			buf.WriteString(warn)
		} else {
			buf.WriteString(ok)
		}
		buf.WriteString(j.Message())
	}
	return buf.String()
}

func (mj MultiJob) Summary() (string, error) {
	c := len(mj)
	var ok, warn, err int
	for _, j := range mj {
		if j.OK != "" {
			ok++
		} else if j.Warn != "" {
			warn++
		} else {
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
