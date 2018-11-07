package cli

import (
	"fmt"

	"github.com/mitchellh/go-wordwrap"
)

func WrapString(lim uint, s string) string {
	return wordwrap.WrapString(s, lim)
}

func WrapSprintf(lim uint, format string, a ...interface{}) string {
	return WrapString(lim, fmt.Sprintf(format, a...))
}

func Wrap(lim uint, args ...interface{}) string {
	var buf buffer
	for i, arg := range args {
		if i > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(fmt.Sprintf("%v", arg))
	}

	return WrapString(lim, string(buf))
}

type buffer []byte

func (b *buffer) WriteString(s string) {
	*b = append(*b, s...)
}

func (b *buffer) WriteByte(c byte) error {
	*b = append(*b, c)
	return nil
}
