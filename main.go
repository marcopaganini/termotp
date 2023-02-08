// This file is part of termOTP, a TOTP program for your terminal.
// https://github.com/marcopaganini/termotp.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/romana/rlog"
)

// BuildVersion holds the current git head version number.
// this is filled in by the build process (make).
var BuildVersion string

// otpEntry holds the representation of the internal vault.
type otpEntry struct {
	issuer  string
	account string
	token   string
}

// die logs a message with rlog.Critical and exists with a return code.
func die(v ...any) {
	if v != nil {
		rlog.Critical(v...)
	}
	os.Exit(1)
}

// usage prints a usage message, defaults for flags, and exits with error.
func usage(s string) {
	if s != "" {
		fmt.Fprintf(os.Stderr, "Please specify input file with --input\n\n")
	}
	flag.Usage()
	flag.PrintDefaults()
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
		return "", fmt.Errorf("No input files match %q", fileglob)
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

func main() {
	// Usage prints the default usage for this program.
	flag.Usage = func() {
		_, program := filepath.Split(os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage:\n  %s [options] [matching_regexp]\n\n", program)
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	var (
		flagInput   = flag.String("input", "", "Input (encrypted) JSON file glob.")
		flagFuzzy   = flag.Bool("fuzzy", false, "Use interactive fuzzy finder.")
		flagVersion = flag.Bool("version", false, "Show program version and exit.")
	)

	flag.Parse()

	if *flagVersion {
		fmt.Printf("Build Version: %s\n", BuildVersion)
		return
	}

	if *flagInput == "" {
		usage("Please specify input file with --input")
	}

	if len(flag.Args()) > 1 {
		usage("Specify one or zero regular expressions to match.")
	}

	// Get input file from the input files glob.
	input, err := inputFile(*flagInput)
	if err != nil {
		die(err)
	}
	rlog.Debugf("Input file: %s", input)

	// By default, match everything (.) unless overriden by an argument.
	r := "."
	if len(flag.Args()) > 0 {
		r = "(?i)" + flag.Args()[0]
	}
	rematch, err := regexp.Compile(r)
	if err != nil {
		die(err)
	}

	db, err := aegisDecrypt(input)
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
		key1 := vault[i].issuer + "/" + vault[i].account
		key2 := vault[j].issuer + "/" + vault[j].account
		return key1 > key2
	})

	// Interactive fuzzy finder.
	if *flagFuzzy {
		token, err := fuzzyFind(vault)
		if err != nil {
			die(err)
		}
		fmt.Println(token)
		return
	}

	// If no interactive mode requested, print a table by default.
	tbl := table.NewWriter()
	automerge := table.RowConfig{AutoMerge: true}

	tbl.AppendHeader(table.Row{"Issuer", "Name", "OTP"}, automerge)
	for _, v := range vault {
		tbl.AppendRow(table.Row{v.issuer, v.account, v.token}, automerge)
	}

	tbl.SortBy([]table.SortBy{
		{Name: "Issuer", Mode: table.Asc},
		{Name: "Name", Mode: table.Asc},
	})
	tbl.SetOutputMirror(os.Stdout)
	tbl.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
	})
	tbl.SetStyle(table.StyleLight)
	tbl.Style().Options.SeparateRows = true
	tbl.Render()
}
