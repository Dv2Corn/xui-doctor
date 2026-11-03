// Package version parses and compares dotted version strings such as
// Xray-core's "26.10.31" or a panel's "3.11.0".
package version

import (
	"strconv"
	"strings"
)

// V is a parsed version. Missing components are zero.
type V struct {
	Parts [3]int
	Raw   string
}

// Parse accepts "26.10.31", "v26.10.31", "Xray 26.10.31 (...)" and similar.
// It returns ok=false when no leading numeric x.y[.z] is found.
func Parse(s string) (V, bool) {
	raw := strings.TrimSpace(s)
	t := raw
	// Skip a product prefix like "Xray " and a leading "v".
	if i := strings.IndexFunc(t, func(r rune) bool { return r >= '0' && r <= '9' }); i > 0 {
		t = t[i:]
	} else if i < 0 {
		return V{Raw: raw}, false
	}
	// Cut at the first character that is not a digit or a dot.
	end := strings.IndexFunc(t, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if end >= 0 {
		t = t[:end]
	}
	fields := strings.Split(strings.Trim(t, "."), ".")
	if len(fields) < 2 {
		return V{Raw: raw}, false
	}
	var v V
	v.Raw = raw
	for i := 0; i < len(fields) && i < 3; i++ {
		n, err := strconv.Atoi(fields[i])
		if err != nil {
			return V{Raw: raw}, false
		}
		v.Parts[i] = n
	}
	return v, true
}

// MustParse is for constants in this module only.
func MustParse(s string) V {
	v, ok := Parse(s)
	if !ok {
		panic("version: bad constant " + s)
	}
	return v
}

// Compare returns -1, 0 or 1.
func Compare(a, b V) int {
	for i := 0; i < 3; i++ {
		switch {
		case a.Parts[i] < b.Parts[i]:
			return -1
		case a.Parts[i] > b.Parts[i]:
			return 1
		}
	}
	return 0
}

// AtLeast reports a >= b.
func AtLeast(a, b V) bool { return Compare(a, b) >= 0 }

func (v V) String() string {
	return strconv.Itoa(v.Parts[0]) + "." + strconv.Itoa(v.Parts[1]) + "." + strconv.Itoa(v.Parts[2])
}
