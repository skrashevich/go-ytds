package main

import (
	"testing"
)

func TestShouldFilterDomain(t *testing.T) {
	filters = []string{"example.com", "test.org", "googlevideo.com"}
	tests := []struct {
		domain   string
		expected bool
	}{
		{"example.com", true},
		{"subdomain.example.com", true},
		{"test.org", true},
		{"another.test.org", true},
		{"notfiltered.com", false},
		{"random.org", false},
		{"example.org", false},
		{"rr5---sn-4g5e6nsz.googlevideo.com", true},
	}

	for _, test := range tests {
		t.Run(test.domain, func(t *testing.T) {
			result := shouldFilterDomain(test.domain)
			if result != test.expected {
				t.Errorf("For domain %s, expected %v but got %v", test.domain, test.expected, result)
			}
		})
	}
}
