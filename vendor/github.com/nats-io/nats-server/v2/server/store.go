// Copyright 2019-2020 The NATS Authors
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

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// StorageType determines how messages are stored for retention.
type StorageType int

const (
	// MemoryStorage specifies in memory only.
	MemoryStorage StorageType = iota
	// FileStorage specifies on disk, designated by the JetStream config StoreDir.
	FileStorage
)

var (
	// ErrStoreClosed is returned when the store has been closed
	ErrStoreClosed = errors.New("store is closed")
	// ErrStoreMsgNotFound when message was not found but was expected to be.
	ErrStoreMsgNotFound = errors.New("no message found")
	// ErrStoreEOF is returned when message seq is greater than the last sequence.
	ErrStoreEOF = errors.New("stream EOF")
	// ErrMaxMsgs is returned when we have discard new as a policy and we reached
	// the message limit.
	ErrMaxMsgs = errors.New("maximum messages exceeded")
	// ErrMaxBytes is returned when we have discard new as a policy and we reached
	// the bytes limit.
	ErrMaxBytes = errors.New("maximum bytes exceeded")
	// ErrStoreSnapshotInProgress is returned when RemoveMsg or EraseMsg is called
	// while a snapshot is in progress.
	ErrStoreSnapshotInProgress = errors.New("snapshot in progress")
	// ErrMsgTooBig is returned when a message is considered too large.
	ErrMsgTooLarge = errors.New("message to large")
)

type StreamStore interface {
	StoreMsg(subj string, hdr, msg []byte) (uint64, int64, error)
	LoadMsg(seq uint64) (subj string, hdr, msg []byte, ts int64, err error)
	RemoveMsg(seq uint64) (bool, error)
	EraseMsg(seq uint64) (bool, error)
	Purge() uint64
	GetSeqFromTime(t time.Time) uint64
	State() StreamState
	StorageBytesUpdate(func(int64))
	UpdateConfig(cfg *StreamConfig) error
	Delete() error
	Stop() error
	ConsumerStore(name string, cfg *ConsumerConfig) (ConsumerStore, error)
	Snapshot(deadline time.Duration, includeConsumers, checkMsgs bool) (*SnapshotResult, error)
}

// RetentionPolicy determines how messages in a set are retained.
type RetentionPolicy int

const (
	// LimitsPolicy (default) means that messages are retained until any given limit is reached.
	// This could be one of MaxMsgs, MaxBytes, or MaxAge.
	LimitsPolicy RetentionPolicy = iota
	// InterestPolicy specifies that when all known observables have acknowledged a message it can be removed.
	InterestPolicy
	// WorkQueuePolicy specifies that when the first worker or subscriber acknowledges the message it can be removed.
	WorkQueuePolicy
)

// Discard Policy determines how we proceed when limits of messages or bytes are hit. The default, DicscardOld will
// remove older messages. DiscardNew will fail to store the new message.
type DiscardPolicy int

const (
	// DiscardOld will remove older messages to return to the limits.
	DiscardOld = iota
	//DiscardNew will error on a StoreMsg call
	DiscardNew
)

// StreamStats is information about the given stream.
type StreamState struct {
	Msgs      uint64    `json:"messages"`
	Bytes     uint64    `json:"bytes"`
	FirstSeq  uint64    `json:"first_seq"`
	FirstTime time.Time `json:"first_ts"`
	LastSeq   uint64    `json:"last_seq"`
	LastTime  time.Time `json:"last_ts"`
	Consumers int       `json:"consumer_count"`
}

// SnapshotResult contains information about the snapshot.
type SnapshotResult struct {
	Reader  io.ReadCloser
	BlkSize int
	NumBlks int
}

// ConsumerStore stores state on consumers for streams.
type ConsumerStore interface {
	State() (*ConsumerState, error)
	Update(*ConsumerState) error
	Stop() error
	Delete() error
}

// SequencePair has both the consumer and the stream sequence. They point to same message.
type SequencePair struct {
	ConsumerSeq uint64 `json:"consumer_seq"`
	StreamSeq   uint64 `json:"stream_seq"`
}

// ConsumerState represents a stored state for a consumer.
type ConsumerState struct {
	// Delivered keeps track of last delivered sequence numbers for both the stream and the consumer.
	Delivered SequencePair `json:"delivered"`
	// AckFloor keeps track of the ack floors for both the stream and the consumer.
	AckFloor SequencePair `json:"ack_floor"`
	// These are both in stream sequence context.
	// Pending is for all messages pending and the timestamp for the delivered time.
	// This will only be present when the AckPolicy is ExplicitAck.
	Pending map[uint64]int64 `json:"pending"`
	// This is for messages that have been redelivered, so count > 1.
	Redelivered map[uint64]uint64 `json:"redelivered"`
}

// TemplateStore stores templates.
type TemplateStore interface {
	Store(*StreamTemplate) error
	Delete(*StreamTemplate) error
}

func jsonString(s string) string {
	return "\"" + s + "\""
}

const (
	limitsPolicyString    = "limits"
	interestPolicyString  = "interest"
	workQueuePolicyString = "workqueue"
)

func (rp RetentionPolicy) String() string {
	switch rp {
	case LimitsPolicy:
		return "Limits"
	case InterestPolicy:
		return "Interest"
	case WorkQueuePolicy:
		return "WorkQueue"
	default:
		return "Unknown Retention Policy"
	}
}

func (rp RetentionPolicy) MarshalJSON() ([]byte, error) {
	switch rp {
	case LimitsPolicy:
		return json.Marshal(limitsPolicyString)
	case InterestPolicy:
		return json.Marshal(interestPolicyString)
	case WorkQueuePolicy:
		return json.Marshal(workQueuePolicyString)
	default:
		return nil, fmt.Errorf("can not marshal %v", rp)
	}
}

func (rp *RetentionPolicy) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case jsonString(limitsPolicyString):
		*rp = LimitsPolicy
	case jsonString(interestPolicyString):
		*rp = InterestPolicy
	case jsonString(workQueuePolicyString):
		*rp = WorkQueuePolicy
	default:
		return fmt.Errorf("can not unmarshal %q", data)
	}
	return nil
}

func (dp DiscardPolicy) String() string {
	switch dp {
	case DiscardOld:
		return "DiscardOld"
	case DiscardNew:
		return "DiscardNew"
	default:
		return "Unknown Discard Policy"
	}
}

func (dp DiscardPolicy) MarshalJSON() ([]byte, error) {
	switch dp {
	case DiscardOld:
		return json.Marshal("old")
	case DiscardNew:
		return json.Marshal("new")
	default:
		return nil, fmt.Errorf("can not marshal %v", dp)
	}
}

func (dp *DiscardPolicy) UnmarshalJSON(data []byte) error {
	switch strings.ToLower(string(data)) {
	case jsonString("old"):
		*dp = DiscardOld
	case jsonString("new"):
		*dp = DiscardNew
	default:
		return fmt.Errorf("can not unmarshal %q", data)
	}
	return nil
}

const (
	memoryStorageString = "memory"
	fileStorageString   = "file"
)

func (st StorageType) String() string {
	switch st {
	case MemoryStorage:
		return strings.Title(memoryStorageString)
	case FileStorage:
		return strings.Title(fileStorageString)
	default:
		return "Unknown Storage Type"
	}
}

func (st StorageType) MarshalJSON() ([]byte, error) {
	switch st {
	case MemoryStorage:
		return json.Marshal(memoryStorageString)
	case FileStorage:
		return json.Marshal(fileStorageString)
	default:
		return nil, fmt.Errorf("can not marshal %v", st)
	}
}

func (st *StorageType) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case jsonString(memoryStorageString):
		*st = MemoryStorage
	case jsonString(fileStorageString):
		*st = FileStorage
	default:
		return fmt.Errorf("can not unmarshal %q", data)
	}
	return nil
}

const (
	ackNonePolicyString     = "none"
	ackAllPolicyString      = "all"
	ackExplicitPolicyString = "explicit"
)

func (ap AckPolicy) MarshalJSON() ([]byte, error) {
	switch ap {
	case AckNone:
		return json.Marshal(ackNonePolicyString)
	case AckAll:
		return json.Marshal(ackAllPolicyString)
	case AckExplicit:
		return json.Marshal(ackExplicitPolicyString)
	default:
		return nil, fmt.Errorf("can not marshal %v", ap)
	}
}

func (ap *AckPolicy) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case jsonString(ackNonePolicyString):
		*ap = AckNone
	case jsonString(ackAllPolicyString):
		*ap = AckAll
	case jsonString(ackExplicitPolicyString):
		*ap = AckExplicit
	default:
		return fmt.Errorf("can not unmarshal %q", data)
	}
	return nil
}

const (
	replayInstantPolicyString  = "instant"
	replayOriginalPolicyString = "original"
)

func (rp ReplayPolicy) MarshalJSON() ([]byte, error) {
	switch rp {
	case ReplayInstant:
		return json.Marshal(replayInstantPolicyString)
	case ReplayOriginal:
		return json.Marshal(replayOriginalPolicyString)
	default:
		return nil, fmt.Errorf("can not marshal %v", rp)
	}
}

func (rp *ReplayPolicy) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case jsonString(replayInstantPolicyString):
		*rp = ReplayInstant
	case jsonString(replayOriginalPolicyString):
		*rp = ReplayOriginal
	default:
		return fmt.Errorf("can not unmarshal %q", data)
	}
	return nil
}

const (
	deliverAllPolicyString       = "all"
	deliverLastPolicyString      = "last"
	deliverNewPolicyString       = "new"
	deliverByStartSequenceString = "by_start_sequence"
	deliverByStartTimeString     = "by_start_time"
	deliverUndefinedString       = "undefined"
)

func (p *DeliverPolicy) UnmarshalJSON(data []byte) error {
	switch string(data) {
	case jsonString(deliverAllPolicyString), jsonString(deliverUndefinedString):
		*p = DeliverAll
	case jsonString(deliverLastPolicyString):
		*p = DeliverLast
	case jsonString(deliverNewPolicyString):
		*p = DeliverNew
	case jsonString(deliverByStartSequenceString):
		*p = DeliverByStartSequence
	case jsonString(deliverByStartTimeString):
		*p = DeliverByStartTime
	default:
		return fmt.Errorf("can not unmarshal %q", data)
	}

	return nil
}

func (p DeliverPolicy) MarshalJSON() ([]byte, error) {
	switch p {
	case DeliverAll:
		return json.Marshal(deliverAllPolicyString)
	case DeliverLast:
		return json.Marshal(deliverLastPolicyString)
	case DeliverNew:
		return json.Marshal(deliverNewPolicyString)
	case DeliverByStartSequence:
		return json.Marshal(deliverByStartSequenceString)
	case DeliverByStartTime:
		return json.Marshal(deliverByStartTimeString)
	default:
		return json.Marshal(deliverUndefinedString)
	}
}
