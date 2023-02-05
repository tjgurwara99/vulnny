package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/token"
	"os"

	"github.com/tjgurwara99/vulnny/internal/sarif"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/vulncheck"
)

const usage = `%[1]s is a tool for finding publically known vulnerabilities withing your codebase.
This application is a tool to find the publically known vulnerabilities withing
your codebase using the go tools vulncheck library, the same library used to
power the govulncheck tool.

The -o flag forces %[1]s to write the resulting SARIF log to the named
output file, instead of the default behavior of writing the SARIF log
to stdout.

Usage:
  %[1]s [-o output] [packages]

Flags:
`

func main() {
	outFile := flag.String("o", "", "File to export the SARIF log to")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), usage, os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	log, err := runVulnny()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal SARIF: %s\n", err.Error())
		os.Exit(1)
	}
	out := os.Stdout
	if *outFile != "" {
		out, err = os.OpenFile(*outFile, os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(1)
		}
		defer out.Close()
	}
	fmt.Fprintln(out, string(data))
}

func runVulnny() (*sarif.Log, error) {
	fset := token.NewFileSet()
	const mode packages.LoadMode = packages.NeedName | packages.NeedImports | packages.NeedTypes |
		packages.NeedSyntax | packages.NeedTypesInfo | packages.NeedDeps |
		packages.NeedModule
	cfg := packages.Config{
		Fset: fset,
		Mode: mode,
	}
	pkgs, err := packages.Load(&cfg, flag.Args()...)
	if err != nil {
		return nil, fmt.Errorf("failed to load packages: %w", err)
	}
	if packages.PrintErrors(pkgs) > 0 {
		return nil, errors.New("package loaded with errors")
	}
	vPkgs := vulncheck.Convert(pkgs)
	sources := []string{"https://vuln.go.dev"}
	dbClient, err := client.NewClient(sources, client.Options{})
	if err != nil {
		return nil, fmt.Errorf("failed to create a client: %w", err)
	}
	res, err := vulncheck.Source(context.Background(), vPkgs, &vulncheck.Config{
		Client: dbClient,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to run source analysis: %w", err)
	}
	log, err := sarif.FromResult(res)
	if err != nil {
		return nil, fmt.Errorf("failed to convert Result to sarif log: %w", err.Error())
	}
	return log, nil
}
