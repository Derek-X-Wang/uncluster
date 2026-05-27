// Package e2e holds the Compose-backed end-to-end test suite. Tests are
// gated behind `-tags e2e` because they require Docker. Run them via:
//
//	cd test/e2e && go test -tags e2e -v -count=1 -timeout 10m
//
// Without the tag, this file is the only one that compiles — it exists so
// `go list` / IDEs can navigate the package. The real test suite lives in
// compose_smoke_test.go (T1a) and additional *_e2e_test.go files added by
// later slices (T1b cert-flow, etc.).
package e2e
