package sarif

import (
	"fmt"
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
	var rules []ReportingDescriptor
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
		shortDescription := fmt.Sprintf("Vulnerable package %s is being used", v.ModPath)
		message := Message{
			Text: shortDescription,
		}
		level := LevelError
		ruleID := v.OSV.ID
		rule := ReportingDescriptor{
			ID:      ruleID,
			Name:    "VulnerablePackage",
			HelpURI: fmt.Sprintf("https://osv.dev/vulnerability/%s", strings.ToLower(v.OSV.ID)),
			ShortDescription: &MultiFormatMessageString{
				Text: shortDescription,
			},
			FullDescription: &MultiFormatMessageString{
				Text: v.OSV.Details,
			},
			Properties: &RDProperties{
				ID:          v.OSV.ID,
				Problem:     string(level),
				Name:        shortDescription,
				Description: v.OSV.Details,
				Kind:        "problem",
				Tags:        []string{"security", "vulnerability"},
			},
		}
		results = append(results, Result{
			Message:   &message,
			RuleID:    ruleID,
			Level:     level,
			Locations: locations,
		})
		rules = append(rules, rule)
	}
	tool := Tool{
		Driver: ToolComponent{
			Name:            "Vulnny",
			SemanitcVersion: "0.0.2",
			InformationURI:  "https://github.com/tjgurwara99/vulnny",
			Rules:           rules,
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
