package passwordvalidator

import (
	"io/ioutil"
	"log"
	"strings"
	"unicode/utf8"
)

func getLength(password string) int {
	//cpc := getCountPerChar()

	return 0
}

func getCountPerChar(password string) map[rune]int {
	const maxNumSameChar = 2
	chars := map[rune]int{}
	for _, c := range password {
		if _, ok := chars[c]; !ok {
			chars[c] = 0
		}
		if chars[c] >= maxNumSameChar {
			continue
		}
		chars[c]++
	}
	return chars
}

func deleteCommonPassSubstrings(passMap passwordsMap, password string) string {
	// Scan across the string, using the largest scanWidths first
	scanWidth := len(password)
	start := 0
	for scanWidth != 0 && len(password) != 0{
		for end := start+scanWidth; end <= len(password); {
			password = deleteSubStringIfBad(passMap, password, start, end)
			start++
			end++
		}
		scanWidth--
		start = 0
	}
	return password
}

func deleteSubStringIfBad(passMap passwordsMap, password string, start int, end int) string {
	subStr := password[start:end]
	if passMap.exists(subStr) {
		password = strings.Replace(password,subStr,"",1)
	}
	return password
}

// is Replace from standard lib, but with start argument
func replaceStart(s, old, new string, n int, start int) string {
	if old == new || n == 0 {
		return s // avoid allocation
	}

	// Compute number of replacements.
	if m := strings.Count(s, old); m == 0 {
		return s // avoid allocation
	} else if n < 0 || m < n {
		n = m
	}

	// Apply replacements to buffer.
	t := make([]byte, len(s)+n*(len(new)-len(old)))
	w := 0
	//start := 0
	for i := 0; i < n; i++ {
		j := start
		if len(old) == 0 {
			if i > 0 {
				_, wid := utf8.DecodeRuneInString(s[start:])
				j += wid
			}
		} else {
			j += strings.Index(s[start:], old)
		}
		w += copy(t[w:], s[start:j])
		w += copy(t[w:], new)
		start = j + len(old)
	}
	w += copy(t[w:], s[start:])
	return string(t[0:w])
}

type passwordsMap map[string]struct{}

func (pwm passwordsMap) exists(password string) bool {
	_, exists := pwm[password]
	return exists
}

var mostCommonPasswords = func() []string{
	b, err := ioutil.ReadFile("most-common-passwords.txt")
	if err != nil {
		log.Fatal(err)
	}

	return strings.Split(string(b),"\n") // consider manually splitting and doing make([]string,0,10000)
}()

