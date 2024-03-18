// This file is part of termOTP, a TOTP program for your terminal.
// https://github.com/marcopaganini/termotp.
package main

import (
	"fmt"

	"github.com/ktr0731/go-fuzzyfinder"
)

const (
	fuzzyPadding      = 3
	defaultIssuerName = "(no issuer name)"
)

// Return the maximum length of one of the otp entries (returned
// by function 'f'.
func maxlen(vault []otpEntry, f func(v otpEntry) string) int {
	max := 0
	for _, entry := range vault {
		length := len(f(entry))
		if length == 0 {
			length = len(defaultIssuerName)
		}
		if length > max {
			max = length
		}
	}
	return max
}

// fuzzyFind opens a fuzzy finder window and allows the user to select the
// desired issuer/account and returns the token.
func fuzzyFind(vault []otpEntry) (string, error) {
	maxIssuerLen := maxlen(vault, func(otp otpEntry) string { return otp.Issuer })
	maxAccountLen := maxlen(vault, func(otp otpEntry) string { return otp.Account })
	maxTokenLen := maxlen(vault, func(otp otpEntry) string { return otp.Token })

	idx, err := fuzzyfinder.Find(
		vault,
		func(i int) string {
			// Default issuer name
			issuer := defaultIssuerName
			if vault[i].Issuer != "" {
				issuer = vault[i].Issuer
			}

			issuer = fmt.Sprintf("%-[1]*s", maxIssuerLen+fuzzyPadding, issuer)
			account := fmt.Sprintf("%-[1]*s", maxAccountLen+fuzzyPadding, vault[i].Account)
			token := fmt.Sprintf("%-[1]*s", maxTokenLen+fuzzyPadding, vault[i].Token)

			return fmt.Sprintf("%s %s %s", issuer, account, token)
		})
	if err != nil {
		return "", err
	}
	return vault[idx].Token, nil
}
