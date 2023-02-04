package main

import (
	"context"
	"flag"
	"fmt"
	"go/token"
	"os"

	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
	"golang.org/x/vuln/vulncheck"
)

func main() {
	flag.Parse()
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
		fmt.Fprintf(os.Stderr, "failed to load packages: %s", err.Error())
		os.Exit(1)
	}
	if packages.PrintErrors(pkgs) > 0 {
		os.Exit(1)
	}
	vPkgs := vulncheck.Convert(pkgs)
	sources := []string{"https://vuln.go.dev"}
	dbClient, err := client.NewClient(sources, client.Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create a client: %s", err.Error())
	}
	res, err := vulncheck.Source(context.Background(), vPkgs, &vulncheck.Config{
		Client: dbClient,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to run source analysis: %v", err)
		os.Exit(1)
	}
	fmt.Println(res)
}
