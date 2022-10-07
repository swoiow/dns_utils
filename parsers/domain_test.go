package parsers

import (
	"reflect"
	"testing"
)

func TestDomainParser(t *testing.T) {
	tests := []struct {
		domain string
		expect bool
	}{
		{domain: "", expect: false},
		{domain: "http://example.com", expect: false},

		{domain: "example.com\r", expect: true},
		{domain: "example.com\n", expect: true},
		{domain: "example.com\r\n", expect: true},

		{domain: " example.com\r\n", expect: true},
		{domain: "	example.com", expect: true},
	}
	for _, tt := range tests {
		t.Run("tt_"+tt.domain, func(t *testing.T) {
			got, _ := Parse(tt.domain, DomainParser)
			if got != tt.expect {
				t.Errorf("parser() got = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestWildcardDomainParser(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want []string
	}{
		{"test_no_wild", "test.io", []string{"test.io"}},
		{"test_wild", "*.test.io", []string{"*.test.io"}},
		{"test_with_comment", "*.test.io #comment", []string{"*.test.io"}},
		{"test_comment_line", "#*.test.io #comment", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WildcardDomainParser(tt.s); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("WildcardDomainParser() = %v, want %v", got, tt.want)
			}
		})
	}
}
