# Vulnny is a simple tool to find vulnerabilities of your Go programs

### Why create yet another analysis tool to do the same thing?

Well simply speaking the govulncheck tool has adopted the OSV format
which is relatively new and for quite some time, SARIF format has
become the defacto standard for Security aggregators. Hence I
decided to use the Go's vulncheck library to get the vulnerabilities
and convert them into the SARIF format. This tool is mostly for
educational purposes, as I wanted to learn about the hurdles tool
adopters might have when thinking about supporting SARIF outputs.