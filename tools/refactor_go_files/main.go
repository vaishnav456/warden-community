// This mechanical refactoring verifies declarations before replacing sources.
// Run with: go run tools/refactor_go_files/main.go -root . -apply
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

func declarationName(d ast.Decl) string {
	switch n := d.(type) {
	case *ast.FuncDecl:
		if n.Recv != nil { return "method:" + n.Name.Name }
		return n.Name.Name
	case *ast.GenDecl:
		if len(n.Specs) != 1 { return "globals" }
		switch s := n.Specs[0].(type) {
		case *ast.TypeSpec: return s.Name.Name
		case *ast.ValueSpec: return s.Names[0].Name
		}
	}
	panic("unsupported declaration")
}

func fingerprints(source []byte) ([]string, error) {
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, "source.go", source, 0)
	if err != nil { return nil, err }
	var result []string
	for _, declaration := range file.Decls {
		if g, ok := declaration.(*ast.GenDecl); ok && g.Tok == token.IMPORT { continue }
		var out bytes.Buffer
		if err := format.Node(&out, set, declaration); err != nil { return nil, err }
		result = append(result, out.String())
	}
	sort.Strings(result)
	return result, nil
}

func split(root, relative string, choose func(string, int, string) string, apply bool) error {
	path := filepath.Join(root, relative)
	source, err := os.ReadFile(path)
	if err != nil { return err }
	set := token.NewFileSet()
	file, err := parser.ParseFile(set, path, source, parser.ParseComments)
	if err != nil { return err }
	imports := map[string]string{}
	for _, spec := range file.Imports {
		p, _ := strconv.Unquote(spec.Path.Value)
		alias := filepath.Base(p)
		entry := spec.Path.Value
		if spec.Name != nil { alias = spec.Name.Name; entry = alias + " " + entry }
		if alias == "_" || alias == "." { return fmt.Errorf("implicit import unsupported: %s", p) }
		imports[alias] = entry
	}
	chunks := map[string][]byte{}
	used := map[string]map[string]bool{}
	previous := set.Position(file.Name.End()).Offset
	for _, declaration := range file.Decls {
		if g, ok := declaration.(*ast.GenDecl); ok && g.Tok == token.IMPORT {
			previous = set.Position(g.End()).Offset
			continue
		}
		start, end := set.Position(declaration.Pos()).Offset, set.Position(declaration.End()).Offset
		name := declarationName(declaration)
		target := choose(name, start, string(source))
		chunks[target] = append(chunks[target], source[previous:end]...)
		if used[target] == nil { used[target] = map[string]bool{} }
		ast.Inspect(declaration, func(n ast.Node) bool {
			if s, ok := n.(*ast.SelectorExpr); ok {
				if ident, ok := s.X.(*ast.Ident); ok { used[target][ident.Name] = true }
			}
			return true
		})
		previous = end
	}
	// Trailing comments belong to the original entry file.
	original := filepath.Base(relative)
	chunks[original] = append(chunks[original], source[previous:]...)
	outputs := map[string][]byte{}
	var actual []string
	for name, chunk := range chunks {
		if name != original {
			if _, err := os.Stat(filepath.Join(filepath.Dir(path), name)); !os.IsNotExist(err) {
				return fmt.Errorf("refusing to overwrite existing file: %s", name)
			}
		}
		var header strings.Builder
		if name == original { header.Write(source[:set.Position(file.Package).Offset]) }
		header.WriteString("package main\n\n")
		var selected []string
		for alias, entry := range imports { if used[name][alias] { selected = append(selected, entry) } }
		sort.Strings(selected)
		if len(selected) > 0 {
			header.WriteString("import (\n" + strings.Join(selected, "\n") + "\n)\n")
		}
		content, err := format.Source(append([]byte(header.String()), chunk...))
		if err != nil { return fmt.Errorf("format %s: %w", name, err) }
		declarations, err := fingerprints(content)
		if err != nil { return err }
		actual = append(actual, declarations...)
		outputs[name] = content
	}
	expected, err := fingerprints(source)
	if err != nil { return err }
	sort.Strings(actual)
	if !reflect.DeepEqual(expected, actual) { return fmt.Errorf("declarations changed: %s", relative) }
	var names []string
	for name := range outputs { names = append(names, name) }
	sort.Strings(names)
	for _, name := range names {
		if apply {
			if err := os.WriteFile(filepath.Join(filepath.Dir(path), name), outputs[name], 0644); err != nil { return err }
		}
		fmt.Printf("%s/%s: %d lines\n", filepath.Dir(relative), name, bytes.Count(outputs[name], []byte("\n")))
	}
	fmt.Printf("Verified %d unchanged declarations in %s\n", len(expected), relative)
	return nil
}

func commandFile(name string, position int, source string) string {
	special := map[string]string{
		"operationWhitelist": "commands.go", "logFn": "commands.go", "dispatchJob": "commands.go",
		"maxRemoteTransferBytes": "commands_files_windows.go", "packetCaptureMu": "commands_diagnostics_windows.go",
		"maxCommandOutputBytes": "commands_execution_windows.go", "cappedCommandOutput": "commands_execution_windows.go",
		"method:Write": "commands_execution_windows.go", "method:Bytes": "commands_execution_windows.go", "boundedCombinedOutput": "commands_execution_windows.go",
		"capturePackets": "commands_diagnostics_windows.go", "getEventLogs": "commands_diagnostics_windows.go", "collectNetworkFlows": "commands_diagnostics_windows.go",
		"windowsUpdate": "commands_patches_windows.go", "reportWindowsPatchInventory": "commands_patches_windows.go",
		"runCmd": "commands_execution_windows.go", "commandExitCode": "commands_execution_windows.go",
		"canonicalJobID": "commands_files_windows.go", "jobStageDir": "commands_files_windows.go", "resolveAllowedPath": "commands_files_windows.go", "canonicalPath": "commands_files_windows.go",
	}
	if target := special[name]; target != "" { return target }
	sections := []struct{ marker, file string }{
		{"// ── Managed device experience", "commands_experience_windows.go"},
		{"// ── BitLocker encryption", "commands_bitlocker_windows.go"},
		{"// ── App install/uninstall", "commands_apps_windows.go"},
		{"// ── User management", "commands_users_windows.go"},
		{"// ── Local user discovery", "commands_user_inventory_windows.go"},
		{"// ── System commands", "commands_execution_windows.go"},
		{"// ── Sysinfo / software inventory", "commands_inventory_windows.go"},
		{"// ── Update agent", "commands_updates_windows.go"},
		{"// ── Peripheral policy", "commands_peripherals_windows.go"},
		{"// ── Remote access", "commands_remote_windows.go"},
		{"// ── Compliance scan", "commands_compliance_windows.go"},
		{"// ── File operations", "commands_files_windows.go"},
	}
	target := "commands.go"
	for _, section := range sections {
		offset := strings.Index(source, section.marker)
		if offset < 0 { panic("missing section: " + section.marker) }
		if position > offset { target = section.file }
	}
	return target
}

func homeFile(name string, _ int, _ string) string {
	groups := map[string][]string{
		"configuration.go": {"config", "decodeB64", "loadConfig"},
		"certificates.go": {"certificateResponse", "loadServingCertificate", "refreshServingCertificate", "watchServingCertificate", "nodeCertificateNeedsRenewal", "ensureNodeCertificate", "tlsClientForPeer"},
		"grant_authorization.go": {"grant", "hasPermission", "verifyPeerCertificate", "verifyGrant", "bearer"},
		"file_crypto.go": {"magic", "magicV2", "chunkSize", "encryptStream", "streamAAD", "encryptStreamForPath", "decryptStream", "decryptStreamForPath", "decryptLegacyStream", "metadataAAD", "metadataHashAAD"},
		"storage_paths.go": {"acquireSpaceLock", "cleanRelative", "pathsFor", "diskUsage", "atomicWrite"},
		"file_storage.go": {"errFileTooLarge", "writeFile", "writeFileVerified", "storeAuthorizedFile", "storeAuthorizedFileVerified"},
		"file_metadata.go": {"fileEntry", "metadata", "prefixUsage", "loadMeta", "listStoredFiles", "listStoredEntries"},
		"file_api.go": {"handleList", "handleFile"},
		"replication.go": {"peer", "replicationStatePath", "loadReplicationState", "recordReplicationSuccess", "replicateFrom"},
		"control_sync.go": {"heartbeatResponse", "heartbeatLoop"},
	}
	for target, names := range groups { for _, candidate := range names { if candidate == name { return target } } }
	if name != "globals" && name != "runConfiguredServer" && name != "main" { panic("unassigned Home declaration: " + name) }
	return "main.go"
}

func main() {
	root := flag.String("root", ".", "repository root")
	apply := flag.Bool("apply", false, "write verified mechanical split")
	flag.Parse()
	for _, item := range []struct{ path string; choose func(string, int, string) string }{
		{"agent-go/commands.go", commandFile}, {"home-node/main.go", homeFile},
	} {
		if err := split(*root, item.path, item.choose, *apply); err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
	}
}
