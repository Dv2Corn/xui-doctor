package i18n

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	for _, c := range []struct {
		flag               string
		lcAll, lcMsg, lang string
		want               Lang
		wantErr            bool
	}{
		{"", "", "", "", EN, false},
		{"", "", "", "ru_RU.UTF-8", RU, false},
		{"", "", "", "en_US.UTF-8", EN, false},
		{"", "", "ru_RU.UTF-8", "en_US.UTF-8", RU, false},  // LC_MESSAGES beats LANG
		{"", "C", "ru_RU.UTF-8", "ru_RU.UTF-8", EN, false}, // LC_ALL beats both
		{"", "ru_UA.UTF-8", "en_US.UTF-8", "", RU, false},
		{"", "", "", "RU", RU, false},
		{"en", "ru_RU.UTF-8", "", "", EN, false}, // the flag beats the environment
		{"ru", "C", "", "en_US.UTF-8", RU, false},
		{"RU", "", "", "", RU, false},
		{"de", "", "", "", EN, true},
	} {
		env := map[string]string{"LC_ALL": c.lcAll, "LC_MESSAGES": c.lcMsg, "LANG": c.lang}
		got, err := Detect(c.flag, func(k string) string { return env[k] })
		if got != c.want || (err != nil) != c.wantErr {
			t.Errorf("Detect(%q, %v) = %q, %v; want %q (error %v)", c.flag, env, got, err, c.want, c.wantErr)
		}
	}
}

func TestEveryMessageHasRussian(t *testing.T) {
	for id, e := range messages {
		if strings.TrimSpace(e.en) == "" || strings.TrimSpace(e.ru) == "" {
			t.Errorf("%s: missing English or Russian text", id)
		}
	}
	for id, e := range plurals {
		en, ru := strings.Split(e.en, "|"), strings.Split(e.ru, "|")
		if len(en) != 2 || len(ru) != 3 {
			t.Errorf("%s: want 2 English and 3 Russian forms, got %d and %d", id, len(en), len(ru))
		}
		for _, f := range append(en, ru...) {
			if strings.TrimSpace(f) == "" || strings.Contains(f, "%") {
				t.Errorf("%s: empty form or format verb in %q", id, f)
			}
		}
	}
}

// verbs parses a format string into argument index -> verb.
func verbs(f string) (map[int]rune, error) {
	out := map[int]rune{}
	arg := 0
	for i := 0; i < len(f); i++ {
		if f[i] != '%' {
			continue
		}
		i++
		if i >= len(f) {
			return nil, errors.New("trailing %")
		}
		if f[i] == '%' {
			continue
		}
		for i < len(f) && strings.ContainsRune("+-# 0", rune(f[i])) {
			i++
		}
		if i < len(f) && f[i] == '[' {
			end := strings.IndexByte(f[i:], ']')
			if end < 0 {
				return nil, errors.New("unclosed [")
			}
			n, err := strconv.Atoi(f[i+1 : i+end])
			if err != nil || n < 1 {
				return nil, fmt.Errorf("bad index %q", f[i:i+end+1])
			}
			arg = n - 1
			i += end + 1
		}
		for i < len(f) && (f[i] >= '0' && f[i] <= '9' || f[i] == '.') {
			i++
		}
		if i >= len(f) || !strings.ContainsRune("sdqv", rune(f[i])) {
			return nil, fmt.Errorf("unsupported verb at %d", i)
		}
		if prev, ok := out[arg]; ok && prev != rune(f[i]) {
			return nil, fmt.Errorf("argument %d used as %%%c and %%%c", arg+1, prev, f[i])
		}
		out[arg] = rune(f[i])
		arg++
	}
	return out, nil
}

func TestFormatVerbsMatch(t *testing.T) {
	for id, e := range messages {
		en, err := verbs(e.en)
		if err != nil {
			t.Errorf("%s en: %v", id, err)
			continue
		}
		ru, err := verbs(e.ru)
		if err != nil {
			t.Errorf("%s ru: %v", id, err)
			continue
		}
		if fmt.Sprint(en) != fmt.Sprint(ru) {
			t.Errorf("%s: verbs differ: en %v, ru %v", id, en, ru)
			continue
		}
		args := make([]any, len(en))
		for i := range args {
			switch en[i] {
			case 'd':
				args[i] = 7
			default:
				args[i] = "x"
			}
		}
		for _, f := range []string{e.en, e.ru} {
			if out := fmt.Sprintf(f, args...); strings.Contains(out, "%!") {
				t.Errorf("%s: %q renders as %q", id, f, out)
			}
		}
	}
}

// TestCatalogMatchesCode fails when code uses an ID the catalog lacks, or
// the catalog keeps an ID no code uses.
func TestCatalogMatchesCode(t *testing.T) {
	re := regexp.MustCompile(`i18n\.(T|Errorf|Plural)\(\s*"([^"]+)"`)
	used := map[string]bool{}
	err := filepath.WalkDir(filepath.Join("..", ".."), func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range re.FindAllStringSubmatch(string(src), -1) {
			id := m[2]
			used[id] = true
			table := messages
			if m[1] == "Plural" {
				table = plurals
			}
			if _, ok := table[id]; !ok {
				t.Errorf("%s: %s(%q) is not in the catalog", path, m[1], id)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var unused []string
	for _, table := range []map[string]entry{messages, plurals} {
		for id := range table {
			if !used[id] {
				unused = append(unused, id)
			}
		}
	}
	sort.Strings(unused)
	if len(unused) > 0 {
		t.Errorf("catalog entries no code uses: %v", unused)
	}
}

func TestRender(t *testing.T) {
	label := T("inbound.label", 3, "main", "vless", 443)
	if got := T("reality.subj_target", label, "example.com:443").In(RU); got != `вход #3 "main" (vless, порт 443), цель example.com:443` {
		t.Errorf("nested ru: %q", got)
	}
	if got := label.String(); got != `inbound #3 "main" (vless, port 443)` {
		t.Errorf("en: %q", got)
	}
	if got := (Text{}).In(RU); got != "" {
		t.Errorf("zero Text: %q", got)
	}
	for n, want := range map[int]string{1: "клиент", 2: "клиента", 4: "клиента", 5: "клиентов", 11: "клиентов",
		14: "клиентов", 21: "клиент", 22: "клиента", 25: "клиентов", 101: "клиент", 111: "клиентов", 0: "клиентов"} {
		if got := Plural("n.client_is", n).In(RU); got != want {
			t.Errorf("ru plural %d: %q want %q", n, got, want)
		}
	}
	if Plural("n.client_is", 1).String() != "client is" || Plural("n.client_is", 2).String() != "clients are" {
		t.Error("en plural")
	}
}

func TestErrors(t *testing.T) {
	inner := Errorf("api.forbidden")
	err := Errorf("api.path_error", "/x", inner)
	if !errors.Is(err, inner) {
		t.Error("Errorf must wrap its error argument")
	}
	if err.Error() != "/x: not permitted for these credentials" {
		t.Errorf("en: %q", err.Error())
	}
	if got := ErrorIn(err, RU); got != "/x: с этими учётными данными нельзя" {
		t.Errorf("ru: %q", got)
	}
	plain := errors.New("connection refused")
	if ErrorIn(plain, RU) != "connection refused" || T("api.login", plain).In(RU) != "вход: connection refused" {
		t.Error("foreign errors keep their text")
	}
}
