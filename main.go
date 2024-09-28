// This file is part of termOTP, a TOTP program for your terminal.
// https://github.com/marcopaganini/termotp.
// (C) 2024 by Marco Paganini
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/romana/rlog"
	"github.com/zalando/go-keyring"
)

// Build holds the current git head version number.
// this is filled in by the build process (make).
var Build string

// otpEntry holds the representation of the internal vault.
type otpEntry struct {
	Issuer  string
	Account string
	Token   string
}

// Keyring constants. User is not your user.
const (
	keyRingService = "termotp"
	keyRingUser    = "anon"
)

// cmdLineFlags contains the command-line flags.
type cmdLineFlags struct {
	input      string
	fuzzy      bool
	fzf        bool
	plain      bool
	json       bool
	setkeyring bool
	usekeyring bool
	version    bool
}

// die logs a message with rlog.Critical and exits with a return code.
func die(v ...any) {
	if v != nil {
		rlog.Critical(v...)
	}
	os.Exit(1)
}

// inputFile expands the glob passed as an argument and returns the file with
// the most recent modification time in the list.
func inputFile(fileglob string) (string, error) {
	files, err := filepath.Glob(fileglob)
	if err != nil {
		return "", err
	}
	if files == nil {
		return "", fmt.Errorf("no input files match %q", fileglob)
	}
	// Find the file with the newest mtime and return.
	var (
		ntime time.Time
		nfile string
	)
	for _, file := range files {
		fi, err := os.Stat(file)
		if err != nil {
			return "", err
		}
		if fi.ModTime().After(ntime) {
			ntime = fi.ModTime()
			nfile = file
		}
	}
	return nfile, nil
}

// outputTable returns a tabular representation of the vault.
func outputTable(vault []otpEntry, flags cmdLineFlags) string {
	// Don't print anything (even a header) if vault is empty.
	if len(vault) == 0 {
		return ""
	}

	// If no interactive mode requested, print a table by default.
	tbl := table.NewWriter()

	// "Plain" style and box used for fzf compatible output.
	styleBoxPlain := table.BoxStyle{
		BottomLeft:       "",
		BottomRight:      "",
		BottomSeparator:  "",
		EmptySeparator:   text.RepeatAndTrim(" ", text.RuneWidthWithoutEscSequences("+")),
		Left:             "",
		LeftSeparator:    "",
		MiddleHorizontal: "",
		MiddleSeparator:  "",
		MiddleVertical:   "",
		PaddingLeft:      " ",
		PaddingRight:     " ",
		PageSeparator:    "",
		Right:            "",
		RightSeparator:   "",
		TopLeft:          "",
		TopRight:         "",
		TopSeparator:     "",
		UnfinishedRow:    "",
	}

	// Default style is "light" unless --fzf or --plan output requested.
	tbl.SetStyle(table.StyleLight)
	if flags.plain {
		stylePlain := table.StyleDefault
		stylePlain.Box = styleBoxPlain
		tbl.SetStyle(stylePlain)
	}

	// Don't automerge if plain or fzf.
	automerge := true
	if flags.plain || flags.fzf {
		automerge = false
	}

	// Don't use headers in the output for fzf.
	if !flags.fzf {
		tbl.AppendHeader(table.Row{"Issuer", "Name", "OTP"})
	}

	for _, v := range vault {
		tbl.AppendRow(table.Row{v.Issuer, v.Account, v.Token})
	}

	tbl.SortBy([]table.SortBy{
		{Name: "Issuer", Mode: table.Asc},
		{Name: "Name", Mode: table.Asc},
	})
	tbl.SetColumnConfigs([]table.ColumnConfig{{Number: 1, AutoMerge: automerge}})
	tbl.Style().Options.SeparateRows = false
	return tbl.Render()
}

// outputJSON outputs a JSON representation of the decrypted vault.
func outputJSON(vault []otpEntry) (string, error) {
	output, err := json.Marshal(vault)
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// parseFlags parses the command line flags and returns a cmdLineFlag struct.
func parseFlags() (cmdLineFlags, error) {
	flags := cmdLineFlags{}

	flag.StringVar(&flags.input, "input", "", "Input (encrypted) JSON file glob.")
	flag.BoolVar(&flags.fuzzy, "fuzzy", false, "Use interactive fuzzy finder.")
	flag.BoolVar(&flags.fzf, "fzf", false, "Use fzf (needs external binary in path).")
	flag.BoolVar(&flags.json, "json", false, "Use JSON output.")
	flag.BoolVar(&flags.plain, "plain", false, "Use plain output (disables fuzzy finder and tabular output.)")
	flag.BoolVar(&flags.version, "version", false, "Show program version and exit.")
	flag.BoolVar(&flags.setkeyring, "set-keyring", false, "Set the keyring password and exit.")
	flag.BoolVar(&flags.usekeyring, "use-keyring", false, "Use keyring stored password.")

	flag.Parse()

	// --setkeyring requires nothing else.
	if flags.setkeyring {
		return flags, nil
	}

	if flags.version {
		fmt.Printf("Build Version: %s\n", Build)
		os.Exit(0)
	}

	// Flag sanity checking.
	if flags.input == "" {
		return cmdLineFlags{}, errors.New("please specify input file with --input")
	}

	// Only one output format allowed.
	n := 0
	for _, v := range []bool{flags.fuzzy, flags.fzf, flags.json, flags.plain} {
		if v {
			n++
		}
	}
	if n > 1 {
		return cmdLineFlags{}, errors.New("please only specify ONE output format")
	}

	if len(flag.Args()) > 1 {
		return cmdLineFlags{}, errors.New("specify one or zero regular expressions to match")
	}

	// FZF uses plain output, with modifications (no headers, no automerge)
	if flags.fzf {
		flags.plain = true
	}

	return flags, nil
}

// fzf runs fzf on the output and return the chosen token.
func fzf(table string) (string, error) {
	cmd := exec.Command("fzf", "--sync")
	cmd.Stderr = os.Stderr

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}
	// Generate output for fzf's stdin.
	for _, line := range strings.Split(table, "\n") {
		// Remove lines containing only spaces added
		// by table. TODO: Find a better fix for this.
		if strings.TrimSpace(line) == "" {
			continue
		}
		fmt.Fprintln(stdin, line)
	}
	stdin.Close()

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	c := strings.TrimSpace(string(output))
	f := strings.Fields(c)
	// This should not happen (empty line)
	if len(f) < 1 {
		return "", nil
	}
	// FZF returns the entire line. The last element contains the token.
	return f[len(f)-1], nil
}

// setkeyring asks for a password and write it to the keyring.
func setkeyring() error {
	password, err := readPassword()
	if err != nil {
		return err
	}

	if err = keyring.Set(keyRingService, keyRingUser, string(password)); err != nil {
		return err
	}
	return nil
}

func main() {
	// Usage prints the default usage for this program.
	flag.Usage = func() {
		_, program := filepath.Split(os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage:\n  %s [options] [matching_regexp]\n\n", program)
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flags, err := parseFlags()
	if err != nil {
		die(err)
	}

	if flags.setkeyring {
		fmt.Println("Please enter the password to be stored in the keyring.")
		if err := setkeyring(); err != nil {
			die(err)
		}
		fmt.Println("Password set. Use --use-keyring to read the password from the keyring.")
		os.Exit(0)
	}

	// Get input file from the input files glob.
	input, err := inputFile(flags.input)
	if err != nil {
		die(err)
	}
	rlog.Debugf("Input file: %s", input)

	// By default, match everything (.) unless overridden by an argument.
	r := "."
	if len(flag.Args()) > 0 {
		r = "(?i)" + flag.Args()[0]
	}
	rematch, err := regexp.Compile(r)
	if err != nil {
		die(err)
	}

	// Read password (from keyboard or keyring) and decrypt aegis vault.
	var (
		password []byte
		secret   string
	)

	if flags.usekeyring {
		secret, err = keyring.Get(keyRingService, keyRingUser)
		password = []byte(secret)
	} else {
		password, err = readPassword()
	}
	if err != nil {
		die(err)
	}

	db, err := aegisDecrypt(input, password)
	if err != nil {
		die(err)
	}
	rlog.Debugf("Decoded JSON:\n%s\n", string(db))

	// Filter and sort vault.
	vault, err := filterAegisVault(db, rematch)
	if err != nil {
		die(err)
	}
	if len(vault) == 0 {
		rlog.Info("No matching entries found.")
		os.Exit(1)
	}
	sort.Slice(vault, func(i, j int) bool {
		key1 := vault[i].Issuer + "/" + vault[i].Account
		key2 := vault[j].Issuer + "/" + vault[j].Account
		return key1 > key2
	})

	switch {
	case flags.fuzzy:
		// Interactive fuzzy finder.
		if flags.fuzzy {
			token, err := fuzzyFind(vault)
			if err != nil {
				die(err)
			}
			fmt.Println(token)
		}
	case flags.fzf:
		t, err := fzf(outputTable(vault, flags))
		if err != nil {
			die(err)
		}
		fmt.Println(t)
	case flags.json:
		output, err := outputJSON(vault)
		if err != nil {
			die(err)
		}
		fmt.Println(output)
	default:
		fmt.Println(outputTable(vault, flags))
	}
}
