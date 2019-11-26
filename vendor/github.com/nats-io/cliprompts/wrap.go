package cliprompts

import (
	"bytes"
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
	var buf bytes.Buffer
	for i, arg := range args {
		if i > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(fmt.Sprintf("%v", arg))
	}

	return WrapString(lim, buf.String())
}
