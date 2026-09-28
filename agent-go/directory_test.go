package main

import "testing"

func TestClassifyWindowsAccount(t *testing.T) {
	tests := []struct{ domain, hostname, want string }{
		{"OFFICE-PC", "office-pc", "local"},
		{"", "OFFICE-PC", "local"},
		{"CORP", "OFFICE-PC", "domain"},
		{"AzureAD", "OFFICE-PC", "entra"},
		{"MicrosoftAccount", "OFFICE-PC", "microsoft"},
	}
	for _, test := range tests {
		if got := classifyWindowsAccount(test.domain, test.hostname); got != test.want {
			t.Fatalf("classifyWindowsAccount(%q, %q) = %q, want %q", test.domain, test.hostname, got, test.want)
		}
	}
}
