package version

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"26.10.31", "26.10.31", true},
		{"v26.9.9", "26.9.9", true},
		{"Xray 26.6.27 (Xray, Penetrates Everything.)", "26.6.27", true},
		{"3.11.0", "3.11.0", true},
		{"1.3", "1.3.0", true},
		{"26.10.31-sp-ios", "26.10.31", true},
		{"Unknown", "", false},
		{"", "", false},
		{"26", "", false},
	}
	for _, c := range cases {
		v, ok := Parse(c.in)
		if ok != c.ok {
			t.Fatalf("Parse(%q) ok=%v want %v", c.in, ok, c.ok)
		}
		if ok && v.String() != c.want {
			t.Fatalf("Parse(%q)=%s want %s", c.in, v, c.want)
		}
	}
}

func TestCompare(t *testing.T) {
	if !AtLeast(MustParse("26.10.31"), MustParse("26.9.8")) {
		t.Fatal("26.10.31 >= 26.9.8")
	}
	if AtLeast(MustParse("26.7.28"), MustParse("26.9.8")) {
		t.Fatal("26.7.28 < 26.9.8")
	}
	if Compare(MustParse("3.11.0"), MustParse("3.11")) != 0 {
		t.Fatal("3.11.0 == 3.11")
	}
	if Compare(MustParse("3.9.0"), MustParse("3.11.0")) != -1 {
		t.Fatal("3.9.0 < 3.11.0")
	}
}
