package passwordvalidator

import (
	"sort"
	"testing"
)

func TestGetLength(t *testing.T) {
	actual := getLength("aaaa")
	expected := 2
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = getLength("12121234")
	expected = 6
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}
}

func TestDeleteCommonPassSubstrings(t *testing.T) {
	actual := deleteCommonPassSubstrings(pm, "password")
	expected := ""
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = deleteCommonPassSubstrings(pm, "oglrpassword")
	expected = "oglr"
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	actual = deleteCommonPassSubstrings(pm, "gtmsupermangtmo#78")
	expected = "gtmgtmo#78"
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}

	// should actually be a high entropy password, maybe should not punish for it
	actual = deleteCommonPassSubstrings(pm, "qwertyuiopfootballsuperman")
	expected = ""
	if actual != expected {
		t.Errorf("Wanted %v, got %v", expected, actual)
	}
}

var pbl = genPasswordsByLength(mostCommonPasswords)
// Does splitting the passwords into maps ordered by password length help with lookup performance?
func BenchmarkLookupPasswordByLength(b *testing.B) {
	for n := 0; n < b.N; n++ {
		pblExists(pbl,"football")
		pblExists(pbl,"password")
		pblExists(pbl,"letmein")
		pblExists(pbl,"love")
		pblExists(pbl,"qwertyuiop")
	}
}

func pblExists(pbl map[int]passwordsMap, password string) bool {
	if pbl[len(password)] == nil {
		return false
	}
	return pbl[len(password)].exists(password)
}

var pm = genPasswordsOnly(mostCommonPasswords)
// Does using a normal map to see existence work well enough?
func BenchmarkLookupPasswordMap(b *testing.B) {
	for n := 0; n < b.N; n++ {
		pm.exists("football")
		pm.exists("password")
		pm.exists("letmein")
		pm.exists("love")
		pm.exists("qwertyuiop")
	}
}

// Does using a bloom filter do better?
//func BenchmarkLookupBloom(b *testing.B) {
//	for n := 0; n < b.N; n++ {
//		// bloom code
//	}
//}

// https://gobyexample.com/sorting-by-functions
type byLength []string

func (s byLength) Len() int {
	return len(s)
}
func (s byLength) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s byLength) Less(i, j int) bool {
	return len(s[i]) < len(s[j])
}

// Used in benchmarking
func genPasswordsByLength(passwords []string) map[int]passwordsMap {
	passwordsByLength := make(map[int]passwordsMap)

	sort.Sort(byLength(passwords))
	for _, password := range passwords {
		if passwordsByLength[len(password)] == nil {
			passwordsByLength[len(password)] = make(passwordsMap)
		}
		passMap := passwordsByLength[len(password)]
		passMap[password] = struct{}{}
	}

	return passwordsByLength
}

// Used in benchmarking
func genPasswordsOnly(passwords []string) passwordsMap {
	passwordsMap := make(passwordsMap, 10000)
	sort.Sort(byLength(passwords))
	for _, password := range passwords {
		passwordsMap[password] = struct{}{}
	}

	return passwordsMap
}
