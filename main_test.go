package main

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/tjgurwara99/mixtape"
	"github.com/tjgurwara99/mixtape/player"
	"golang.org/x/tools/go/packages"
	"golang.org/x/vuln/client"
)

func setTestBuildDir(elems ...string) cfgOpts {
	return func(c *packages.Config) error {
		wd, err := os.Getwd()
		if err != nil {
			return err
		}
		data := []string{wd}
		data = append(data, elems...)
		c.Dir = filepath.Join(data...)
		return nil
	}
}

func TestRunVulnny(t *testing.T) {
	cassette, err := mixtape.Load("testdata/vuln/cassette")
	if err != nil {
		t.Fatal(err)
	}
	transport := player.New(cassette, player.Record, http.DefaultTransport)
	c := &http.Client{
		Transport: transport,
	}
	sarif, err := runVulnny(client.Options{
		HTTPClient: c,
	}, setTestBuildDir("testdata", "vuln"))
	if err != nil {
		t.Fatal(err)
	}
	if len(sarif.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(sarif.Runs))
	}
	if len(sarif.Runs[0].Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(sarif.Runs[0].Results))
	}
	if sarif.Runs[0].Results[0].RuleID != "GO-2021-0113" {
		t.Fatalf("expected rule ID to be GO-2021-0113, got %s", sarif.Runs[0].Results[0].RuleID)
	}
	if sarif.Runs[0].Results[0].Level != "error" {
		t.Fatalf("expected level to be error, got %s", sarif.Runs[0].Results[0].Level)
	}
	if sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI != "testdata/vuln/vuln.go" {
		t.Fatalf("expected URI to be testdata/vuln/vuln.go, got %s", sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URIBaseID != "%SRCROOT%" {
		t.Fatalf("expected URI to be testdata/vuln/vuln.go, got %s", sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	if sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.StartLine != 12 {
		t.Fatalf("expected start line to be 12, got %d", sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.StartLine)
	}
	if sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.StartColumn != 16 {
		t.Fatalf("expected start column to be 16, got %d", sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.StartColumn)
	}
	if sarif.Runs[0].Results[0].Message.Text != "Vulnerable package golang.org/x/text is being used" {
		t.Fatalf("expected message to be Vulnerable package golang.org/x/text is being used, got %s", sarif.Runs[0].Results[0].Message.Text)
	}
}
