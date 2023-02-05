package sarif

import (
	"go/build"
	"os"
	"strings"

	"github.com/tjgurwara99/vulnny/internal/slice"
	"golang.org/x/vuln/vulncheck"
)

func FromResult(r *vulncheck.Result) (*Log, error) {
	filtered := slice.Filter(r.Vulns, func(i *vulncheck.Vuln) bool {
		return i.CallSink != 0
	})
	var j int
	var results []Result
	for i, v := range filtered {
		fn, ok := r.Calls.Functions[v.CallSink]
		if !ok {
			j++
			continue
		}
		var locations []Location
		for _, cs := range fn.CallSites {
			uri, skip := getURI(cs.Pos.Filename)
			if skip {
				continue
			}
			aLoc := ArtifactLocation{
				URIBaseID: "%SRCROOT%",
				URI:       uri,
				Index:     i - j,
			}
			region := Region{
				StartLine:   cs.Pos.Line,
				StartColumn: cs.Pos.Column,
			}
			pLoc := PhysicalLocation{
				ArtifactLocation: &aLoc,
				Region:           &region,
			}
			loc := Location{
				PhysicalLocation: &pLoc,
			}
			locations = append(locations, loc)
		}
		message := Message{
			Text: v.OSV.Details,
		}
		level := LevelError
		ruleID := v.OSV.ID
		results = append(results, Result{
			Message:   &message,
			Level:     level,
			RuleID:    ruleID,
			Locations: locations,
		})
	}
	tool := Tool{
		Driver: ToolComponent{
			Name: "Vulnny",
		},
	}
	runs := []Run{
		{
			Tool:    tool,
			Results: results,
		},
	}
	return &Log{
		Version: Version,
		Schema:  Schema,
		Runs:    runs,
	}, nil
}

func getURI(filename string) (_ string, skip bool) {
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = build.Default.GOPATH
	}
	if strings.HasPrefix(filename, gopath) {
		return "", true
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", true
	}
	return strings.TrimPrefix(filename, wd+"/"), false
}
