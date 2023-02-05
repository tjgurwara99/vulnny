package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"go/token"
	"os"

	"github.com/tjgurwara99/vulnny/internal/sarif"
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
	log, err := sarif.FromResult(res)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to convert Result to sarif log: %s", err.Error())
	}
	data, _ := json.MarshalIndent(log, "", " ")
	fmt.Println(string(data))
}
