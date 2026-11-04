// Package i18n holds the tool's human-readable messages in English and
// Russian and picks the output language.
//
// A message is a Text: an ID from the catalog plus its arguments. It is
// rendered only when printed, so the same finding can be shown in Russian on
// the terminal and kept in English in JSON output. Arguments that are Texts
// or *Error values are rendered in the same language.
package i18n

import (
	"fmt"
	"strings"
)

// Lang is an output language.
type Lang string

// Supported languages. EN is the default.
const (
	EN Lang = "en"
	RU Lang = "ru"
)

// Parse accepts "en" or "ru" (any case).
func Parse(s string) (Lang, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "en":
		return EN, nil
	case "ru":
		return RU, nil
	}
	return EN, fmt.Errorf("unknown language %q: use en or ru", s)
}

// Detect returns the language from the --lang flag value or, when it is
// empty, from the first non-empty of LC_ALL, LC_MESSAGES and LANG: a value
// starting with "ru" selects Russian, anything else English.
func Detect(flag string, getenv func(string) string) (Lang, error) {
	if strings.TrimSpace(flag) != "" {
		return Parse(flag)
	}
	for _, name := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		if v := strings.TrimSpace(getenv(name)); v != "" {
			if strings.HasPrefix(strings.ToLower(v), "ru") {
				return RU, nil
			}
			return EN, nil
		}
	}
	return EN, nil
}

// Text is a catalog message with its arguments. The zero Text renders as "".
type Text struct {
	ID     string
	Args   []any
	n      int
	plural bool
}

// T returns the message id with args; args may be Texts, errors or plain values.
func T(id string, args ...any) Text { return Text{ID: id, Args: args} }

// Plural returns the form of the plural entry id that fits the count n.
func Plural(id string, n int) Text { return Text{ID: id, n: n, plural: true} }

// String renders the text in English.
func (t Text) String() string { return t.In(EN) }

// In renders the text in language l. An unknown ID renders as itself.
func (t Text) In(l Lang) string {
	if t.ID == "" {
		return ""
	}
	if t.plural {
		e, ok := plurals[t.ID]
		if !ok {
			return t.ID
		}
		if l == RU {
			return strings.Split(e.ru, "|")[ruForm(t.n)]
		}
		forms := strings.Split(e.en, "|")
		if t.n == 1 {
			return forms[0]
		}
		return forms[1]
	}
	e, ok := messages[t.ID]
	if !ok {
		return t.ID
	}
	format := e.en
	if l == RU {
		format = e.ru
	}
	args := make([]any, len(t.Args))
	for i, a := range t.Args {
		switch v := a.(type) {
		case Text:
			args[i] = v.In(l)
		case error:
			args[i] = ErrorIn(v, l)
		default:
			args[i] = a
		}
	}
	return fmt.Sprintf(format, args...)
}

// ruForm picks 0 (1, 21, ...), 1 (2-4, 22-24, ...) or 2 (5-20, 25-30, ...).
func ruForm(n int) int {
	if n < 0 {
		n = -n
	}
	if n%100 >= 11 && n%100 <= 14 {
		return 2
	}
	switch n % 10 {
	case 1:
		return 0
	case 2, 3, 4:
		return 1
	}
	return 2
}

// Error is an error whose text comes from the catalog.
type Error struct {
	Text    Text
	wrapped error
}

// Errorf returns an *Error for message id. The first error among args is
// wrapped, so errors.Is and errors.As see it.
func Errorf(id string, args ...any) error {
	e := &Error{Text: T(id, args...)}
	for _, a := range args {
		if err, ok := a.(error); ok {
			e.wrapped = err
			break
		}
	}
	return e
}

func (e *Error) Error() string { return e.Text.In(EN) }

// Unwrap returns the wrapped error, if any.
func (e *Error) Unwrap() error { return e.wrapped }

// ErrorIn renders err in language l when err itself is an *Error; any other
// error (from the standard library or the network) keeps its own text.
func ErrorIn(err error, l Lang) string {
	if e, ok := err.(*Error); ok {
		return e.Text.In(l)
	}
	return err.Error()
}
