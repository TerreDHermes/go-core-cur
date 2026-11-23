// Package verdictmark stamps the final verdict and tells our text from any other.
//
// The whole mark is this file. It uses only the standard library, so it can be
// copied into another program without the rest of this service. Stamp writes
// the sign. Ours reports whether a text carries it. Count splits a pile of
// texts into ours and the rest.
//
// The sign is eight invisible format characters and has no glyph and no width:
// U+200D U+200C U+200D U+200D U+200C U+200C U+200D U+200C.
// Stamp places it right after the first sentence, before the following space,
// and again at the very end. One sentence has those two places in common, so
// the sign is written once. A dot between digits, as in 1.22.5, is not a
// sentence end.
package verdictmark

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Mark is the invisible signature. Search for this exact sequence.
const Mark = "\u200d\u200c\u200d\u200d\u200c\u200c\u200d\u200c"

// Stamp inserts Mark into a finished verdict. Empty text and text that already
// carries the sign are returned unchanged.
func Stamp(text string) string {
	text = strings.TrimSpace(text)
	if text == "" || strings.Contains(text, Mark) {
		return text
	}
	at, ok := firstSentenceEnd(text)
	if !ok {
		return text + Mark
	}
	if strings.TrimSpace(text[at:]) == "" {
		return text[:at] + Mark
	}
	return text[:at] + Mark + text[at:] + Mark
}

// Ours reports whether text was stamped by this service.
func Ours(text string) bool {
	return strings.Contains(text, Mark)
}

// Count splits texts into those that carry the sign and those that do not.
func Count(texts []string) (ours, foreign int) {
	for _, text := range texts {
		if Ours(text) {
			ours++
			continue
		}
		foreign++
	}
	return ours, foreign
}

// firstSentenceEnd is the byte offset just after the first sentence mark.
// The mark is '.', '!', '?', '…', or a run of dots. A decimal dot does not count.
func firstSentenceEnd(text string) (int, bool) {
	for i := 0; i < len(text); {
		r, size := utf8.DecodeRuneInString(text[i:])
		switch r {
		case '!', '?', '…':
			return i + size, true
		case '.':
			if decimalDot(text, i) {
				i += size
				continue
			}
			j := i + size
			for j < len(text) {
				next, n := utf8.DecodeRuneInString(text[j:])
				if next != '.' {
					break
				}
				j += n
			}
			return j, true
		}
		i += size
	}
	return 0, false
}

func decimalDot(text string, i int) bool {
	if i == 0 || i+1 >= len(text) {
		return false
	}
	prev, _ := utf8.DecodeLastRuneInString(text[:i])
	next, _ := utf8.DecodeRuneInString(text[i+1:])
	return unicode.IsDigit(prev) && unicode.IsDigit(next)
}
