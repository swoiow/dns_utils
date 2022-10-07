package parsers

import "strings"

const (
	wildcardMark = "*."
)

func DomainParser(s string) []string {
	d := strings.TrimSpace(s)
	return []string{d}
}

func WildcardDomainParser(s string) []string {
	s = strings.TrimSpace(s)
	if strings.Index(s, "#") > 0 {
		s = strings.Split(s, "#")[0]
	}

	d := strings.TrimSpace(s)
	if strings.HasPrefix(d, wildcardMark) && IsDomainName(strings.TrimPrefix(d, wildcardMark)) {
		return []string{d}
	} else {
		if IsDomainName(strings.TrimPrefix(d, wildcardMark)) {
			return []string{d}
		}
	}
	return nil
}
