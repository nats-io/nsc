# Tablewriter

This is a legit fork of [apcera/termtables](https://github.com/apcera/termtables). This version is portable
and does not rely on platform-dependent stuff like locale and term info.

A [Go](http://golang.org) port of the Ruby library [terminal-tables](https://github.com/visionmedia/terminal-table) for fast and simple ASCII table generation.

## Installation

```bash
go get github.com/xlab/tablewriter
```

## Go Style Documentation

[http://godoc.org/github.com/xlab/tablewriter](http://godoc.org/github.com/xlab/tablewriter)

## Basic Usage

```go
package main

import (
  "fmt"
  "github.com/xlab/tablewriter"
)

func main() {
  table := tablewriter.CreateTable()

  table.AddHeaders("Name", "Age")
  table.AddRow("John", "30")
  table.AddRow("Sam", 18)
  table.AddRow("Julie", 20.14)

  fmt.Println(table.Render())
}
```

Result:

```
+-------+-------+
| Name  | Age   |
+-------+-------+
| John  | 30    |
| Sam   | 18    |
| Julie | 20.14 |
+-------+-------+
```

## Advanced Usage

The package function-call `EnableUTF8()` will cause any tables created after
that point to use Unicode box-drawing characters for the table lines.

Calling `SetModeHTML(true)` will cause any tables created after that point
to be emitted in HTML, while `SetModeMarkdown(true)` will trigger Markdown.
Neither should result in changes to later API to get the different results;
the primary intended use-case is extracting the same table, but for
documentation.

The table method `.AddSeparator()` inserts a rule line in the output.  This
only applies in normal terminal output mode.

The table method `.AddTitle()` adds a title to the table; in terminal output,
this is an initial row; in HTML, it's a caption.  In Markdown, it's a line of
text before the table, prefixed by `Table: `.

The table method `.SetAlign()` takes an alignment and a column number
(indexing starts at 1) and changes all _current_ cells in that column to have
the given alignment.  It does not change the alignment of cells added to the
table after this call.  Alignment is only stored on a per-cell basis.

## Known Issues

Normal output:

* `.SetAlign()` does not affect headers.

Markdown output mode:

* When emitting Markdown, the column markers are not re-flowed if a vertical
  bar is an element of a cell, causing an escape to take place; since Markdown
  is often converted to HTML, this only affects text viewing.
* A title in Markdown is not escaped against all possible forms of Markdown
  markup (to avoid adding a dependency upon a Markdown library, as supported
  syntax can vary).
* Markdown requires headers, so a dummy header will be inserted if needed.
* Table alignment is not reflected in Markdown output.
