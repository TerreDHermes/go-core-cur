package scan

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"cve-patch-viewer/internal/applicability/task"
)

// typeHeader matches a Go struct or interface declaration, including a simple
// type parameter list. The name is the changed type a patch can introduce
// without touching a function.
var typeHeader = regexp.MustCompile(`\btype\s+([A-Za-z_][A-Za-z0-9_]*)(?:\[[^\]\n]*\])?\s+(?:struct|interface)\b`)

var packageClause = regexp.MustCompile(`(?m)^package\s+([A-Za-z_][A-Za-z0-9_]*)`)

type locatedFunc struct {
	File string
	Func namedFunc
	rank int
}

type typeFallback struct {
	Funcs      []locatedFunc
	Unused     []string
	Unnamed    bool
	Unread     bool
	Unresolved bool
	HadGo      bool
	Cancelled  bool
}

func functionsFromChangedTypes(ctx context.Context, repoPath string, files []task.PatchFile, matches []task.PatchFileMatch, stdlib bool, goroot string) typeFallback {
	var out typeFallback
	seenType := map[string]bool{}
	var hits []locatedFunc
	for _, match := range matches {
		if ctx.Err() != nil {
			out.Cancelled = true
			return out
		}
		if !match.Found || !strings.HasSuffix(match.Filename, ".go") || strings.HasSuffix(match.Filename, "_test.go") {
			continue
		}
		out.HadGo = true
		diff := patchText(files, match.Filename)
		names := typesInPatch(diff)
		if len(names) == 0 {
			body, err := os.ReadFile(absMatch(repoPath, match.Path))
			if err != nil {
				out.Unread = true
				continue
			}
			names = enclosingTypes(string(body), diff)
		}
		if len(names) == 0 {
			out.Unnamed = true
			continue
		}
		for _, name := range names {
			if seenType[name] {
				continue
			}
			seenType[name] = true
			found, status := functionsUsingType(ctx, repoPath, match.Path, name, stdlib, goroot)
			switch status {
			case typeUseCancelled:
				out.Cancelled = true
				return out
			case typeUseUnread:
				out.Unread = true
			case typeUseUnresolved:
				out.Unresolved = true
			case typeUseNone:
				out.Unused = append(out.Unused, name)
			default:
				hits = append(hits, found...)
			}
		}
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].rank != hits[j].rank {
			return hits[i].rank < hits[j].rank
		}
		if hits[i].File != hits[j].File {
			return hits[i].File < hits[j].File
		}
		if hits[i].Func.Recv != hits[j].Func.Recv {
			return hits[i].Func.Recv < hits[j].Func.Recv
		}
		return hits[i].Func.Name < hits[j].Func.Name
	})
	seenFn := map[string]bool{}
	for _, hit := range hits {
		key := hit.File + " " + hit.Func.Recv + "." + hit.Func.Name
		if seenFn[key] {
			continue
		}
		seenFn[key] = true
		out.Funcs = append(out.Funcs, hit)
		if len(out.Funcs) >= maxReachFuncs {
			break
		}
	}
	return out
}

type typeUseStatus int

const (
	typeUseFound typeUseStatus = iota
	typeUseNone
	typeUseUnread
	typeUseUnresolved
	typeUseCancelled
)

func functionsUsingType(ctx context.Context, repoPath, origin, typeName string, stdlib bool, goroot string) ([]locatedFunc, typeUseStatus) {
	abs := absMatch(repoPath, origin)
	pkgName := packageNameOf(abs)
	if pkgName == "" {
		return nil, typeUseUnread
	}
	importPath := importPathOf(repoPath, origin)
	if stdlib {
		if pkg := stdlibImportPath(goroot, abs); pkg != "" {
			importPath = pkg
		}
	}
	exported := exportedName(typeName)
	if exported && importPath == "" {
		return nil, typeUseUnresolved
	}
	roots := typeSearchRoots(repoPath, origin, abs, exported, stdlib, goroot)
	parsedOrigin := false
	originParsed := false
	var hits []locatedFunc
	var methods []locatedFunc
	var outers []struct{ dir, name string }
	var vars []struct{ dir, name string }
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "testdata" || name == "node_modules" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil || file.Name == nil {
				return nil
			}
			if filepath.Clean(path) == filepath.Clean(abs) {
				originParsed = true
			}
			same := filepath.Clean(filepath.Dir(path)) == filepath.Clean(filepath.Dir(abs))
			if same {
				parsedOrigin = true
			}
			bare, qualifier := mentionMode(file, same, exported, importPath, pkgName)
			if !bare && qualifier == "" {
				return nil
			}
			display := displayPath(repoPath, path)
			dir := filepath.Clean(filepath.Dir(path))
			for _, decl := range file.Decls {
				switch node := decl.(type) {
				case *ast.FuncDecl:
					if node.Name == nil || node.Name.Name == "" {
						continue
					}
					fn := namedFunc{Name: node.Name.Name, Recv: recvTypeName(node)}
					item := locatedFunc{File: display, Func: fn}
					if fn.Recv != "" {
						methods = append(methods, item)
					}
					switch {
					case bare && receiverMentions(node, typeName):
						item.rank = 0
					case signatureMentions(node, typeName, bare, qualifier):
						item.rank = 1
					case bodyMentions(node, typeName, bare, qualifier):
						item.rank = 2
					default:
						continue
					}
					hits = append(hits, item)
				case *ast.GenDecl:
					collectTypeDecls(node, dir, typeName, bare, qualifier, &outers, &vars)
				}
			}
			return nil
		})
		if err != nil {
			if ctx.Err() != nil {
				return nil, typeUseCancelled
			}
		}
	}
	if !parsedOrigin || !originParsed {
		return nil, typeUseUnread
	}
	for _, outer := range outers {
		for _, method := range methods {
			if method.Func.Recv != outer.name {
				continue
			}
			if filepath.Clean(filepath.Dir(absMatch(repoPath, method.File))) != outer.dir {
				continue
			}
			method.rank = 3
			hits = append(hits, method)
		}
	}
	for _, variable := range vars {
		if utf8.RuneCountInString(variable.name) < 4 {
			continue
		}
		extra := functionsMentioningIdent(ctx, repoPath, variable.dir, variable.name)
		if ctx.Err() != nil {
			return nil, typeUseCancelled
		}
		for _, item := range extra {
			item.rank = 4
			hits = append(hits, item)
		}
	}
	if len(hits) == 0 {
		return nil, typeUseNone
	}
	return hits, typeUseFound
}

func collectTypeDecls(decl *ast.GenDecl, dir, typeName string, bare bool, qualifier string, outers *[]struct{ dir, name string }, vars *[]struct{ dir, name string }) {
	for _, spec := range decl.Specs {
		switch node := spec.(type) {
		case *ast.TypeSpec:
			st, ok := node.Type.(*ast.StructType)
			if !ok || node.Name == nil || node.Name.Name == typeName || !structUsesType(st, typeName, bare, qualifier) {
				continue
			}
			*outers = append(*outers, struct{ dir, name string }{dir, node.Name.Name})
		case *ast.ValueSpec:
			if !mentionsType(node.Type, typeName, bare, qualifier) && !valuesMention(node.Values, typeName, bare, qualifier) {
				continue
			}
			for _, name := range node.Names {
				if name == nil || name.Name == "" || name.Name == "_" {
					continue
				}
				*vars = append(*vars, struct{ dir, name string }{dir, name.Name})
			}
		}
	}
}

func functionsMentioningIdent(ctx context.Context, repoPath, dir, ident string) []locatedFunc {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []locatedFunc
	for _, entry := range entries {
		if ctx.Err() != nil {
			return out
		}
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		path := filepath.Join(dir, name)
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Name.Name == "" {
				continue
			}
			if !mentionsType(fn.Type, ident, true, "") && !mentionsType(fn.Body, ident, true, "") {
				continue
			}
			out = append(out, locatedFunc{
				File: displayPath(repoPath, path),
				Func: namedFunc{Name: fn.Name.Name, Recv: recvTypeName(fn)},
			})
		}
	}
	return out
}

func typeSearchRoots(repoPath, origin, abs string, exported, stdlib bool, goroot string) []string {
	pkgDir := filepath.Clean(filepath.Dir(abs))
	if !exported {
		return []string{pkgDir}
	}
	var roots []string
	if stdlib && goroot != "" {
		roots = append(roots, filepath.Join(goroot, "src"))
	}
	if mod, ok := moduleDirForFile(repoPath, origin); ok {
		roots = append(roots, mod)
	} else if repoPath != "" {
		roots = append(roots, filepath.Clean(repoPath))
	}
	if len(roots) == 0 {
		roots = append(roots, pkgDir)
	}
	return outermostDirs(roots)
}

func outermostDirs(dirs []string) []string {
	clean := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		dir = filepath.Clean(dir)
		if dir == "" {
			continue
		}
		dup := false
		for _, existing := range clean {
			if existing == dir {
				dup = true
				break
			}
		}
		if !dup {
			clean = append(clean, dir)
		}
	}
	var out []string
	for _, dir := range clean {
		inside := false
		for _, other := range clean {
			if other == dir {
				continue
			}
			rel, err := filepath.Rel(other, dir)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				inside = true
				break
			}
		}
		if !inside {
			out = append(out, dir)
		}
	}
	return out
}

func mentionMode(file *ast.File, same, exported bool, importPath, pkgName string) (bare bool, qualifier string) {
	if same {
		bare = true
	}
	if !exported || importPath == "" {
		return bare, ""
	}
	for _, spec := range file.Imports {
		path, err := strconvUnquote(spec.Path)
		if err != nil || path != importPath {
			continue
		}
		if spec.Name == nil {
			return bare, pkgName
		}
		switch spec.Name.Name {
		case "_":
			return bare, ""
		case ".":
			return true, ""
		default:
			return bare, spec.Name.Name
		}
	}
	return bare, ""
}

func strconvUnquote(lit *ast.BasicLit) (string, error) {
	if lit == nil {
		return "", fmt.Errorf("empty import")
	}
	return strconv.Unquote(lit.Value)
}

func receiverMentions(fn *ast.FuncDecl, typeName string) bool {
	return fn != nil && mentionsType(fn.Recv, typeName, true, "")
}

func signatureMentions(fn *ast.FuncDecl, typeName string, bare bool, qualifier string) bool {
	return fn != nil && mentionsType(fn.Type, typeName, bare, qualifier)
}

func bodyMentions(fn *ast.FuncDecl, typeName string, bare bool, qualifier string) bool {
	return fn != nil && mentionsType(fn.Body, typeName, bare, qualifier)
}

func structUsesType(st *ast.StructType, typeName string, bare bool, qualifier string) bool {
	if st == nil || st.Fields == nil {
		return false
	}
	for _, field := range st.Fields.List {
		if mentionsType(field.Type, typeName, bare, qualifier) {
			return true
		}
	}
	return false
}

func valuesMention(values []ast.Expr, typeName string, bare bool, qualifier string) bool {
	for _, value := range values {
		if mentionsType(value, typeName, bare, qualifier) {
			return true
		}
	}
	return false
}

func mentionsType(node ast.Node, typeName string, bare bool, qualifier string) bool {
	if node == nil || typeName == "" {
		return false
	}
	selectors := map[*ast.Ident]bool{}
	ast.Inspect(node, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if ok && sel.Sel != nil {
			selectors[sel.Sel] = true
		}
		return true
	})
	found := false
	ast.Inspect(node, func(n ast.Node) bool {
		if found || n == nil {
			return false
		}
		switch e := n.(type) {
		case *ast.Ident:
			if bare && e.Name == typeName && !selectors[e] {
				found = true
			}
		case *ast.SelectorExpr:
			if qualifier != "" && e.Sel != nil && e.Sel.Name == typeName {
				if id, ok := e.X.(*ast.Ident); ok && id.Name == qualifier {
					found = true
				}
			}
		}
		return true
	})
	return found
}

func recvTypeName(fn *ast.FuncDecl) string {
	if fn == nil || fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	return typeBaseName(fn.Recv.List[0].Type)
}

func typeBaseName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return typeBaseName(t.X)
	case *ast.IndexExpr:
		return typeBaseName(t.X)
	case *ast.IndexListExpr:
		return typeBaseName(t.X)
	case *ast.SelectorExpr:
		if t.Sel != nil {
			return t.Sel.Name
		}
	}
	return ""
}

func packageNameOf(path string) string {
	body, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	m := packageClause.FindStringSubmatch(string(body))
	if m == nil {
		return ""
	}
	return m[1]
}

func exportedName(name string) bool {
	r, _ := utf8.DecodeRuneInString(name)
	return unicode.IsUpper(r)
}

func displayPath(repoPath, abs string) string {
	rel, err := filepath.Rel(filepath.Clean(repoPath), filepath.Clean(abs))
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return abs
	}
	return "./" + filepath.ToSlash(rel)
}

func typesInPatch(diff string) []string {
	var out []string
	seen := map[string]bool{}
	add := func(line string) {
		m := typeHeader.FindStringSubmatch(line)
		if m == nil || seen[m[1]] {
			return
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "@@") {
			if i := strings.LastIndex(line, "@@"); i >= 0 {
				add(line[i+2:])
			}
			continue
		}
		if line == "" {
			continue
		}
		switch line[0] {
		case '+', '-', ' ':
			add(strings.TrimSpace(line[1:]))
		}
	}
	return out
}

func diffAnchors(diff string) []string {
	context := anchorsFrom(diff, func(mark byte) bool { return mark == ' ' || mark == '-' })
	if len(context) > 0 {
		return context
	}
	return anchorsFrom(diff, func(mark byte) bool { return mark == '+' })
}

func anchorsFrom(diff string, keep func(byte) bool) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(diff, "\n") {
		if line == "" || strings.HasPrefix(line, "@@") || strings.HasPrefix(line, "diff ") || strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "index ") {
			continue
		}
		if !keep(line[0]) {
			continue
		}
		text := strings.TrimSpace(line[1:])
		if !usefulAnchor(text) || seen[text] {
			continue
		}
		seen[text] = true
		out = append(out, text)
	}
	return out
}

func usefulAnchor(text string) bool {
	switch text {
	case "", "{", "}", "(", ")":
		return false
	}
	if strings.HasPrefix(text, "//") || strings.HasPrefix(text, "/*") || strings.HasPrefix(text, "*") {
		return false
	}
	if strings.HasPrefix(text, "func ") || strings.HasPrefix(text, "func(") || strings.HasPrefix(text, "type ") || strings.HasPrefix(text, "package ") {
		return false
	}
	for _, r := range text {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

func enclosingTypes(src, diff string) []string {
	anchors := map[string]struct{}{}
	for _, anchor := range diffAnchors(diff) {
		anchors[anchor] = struct{}{}
	}
	if len(anchors) == 0 {
		return nil
	}
	var current string
	depth := 0
	var found []string
	seen := map[string]bool{}
	for _, line := range strings.Split(src, "\n") {
		trim := strings.TrimSpace(line)
		if depth == 0 {
			if m := typeHeader.FindStringSubmatch(trim); m != nil && strings.Contains(trim, "{") {
				current = m[1]
			} else {
				current = ""
			}
		}
		if current != "" && depth > 0 {
			if _, ok := anchors[trim]; ok && !seen[current] {
				seen[current] = true
				found = append(found, current)
			}
		}
		depth += strings.Count(line, "{") - strings.Count(line, "}")
		if depth <= 0 {
			depth = 0
			current = ""
		}
	}
	return found
}

func unusedTypeDetail(names []string) string {
	label := "тип " + strings.Join(names, ", ")
	if len(names) > 1 {
		label = "типы " + strings.Join(names, ", ")
	}
	return label + " не используется в модуле: уязвимый код недостижим, уязвимости в этой сборке нет"
}

func typeUnknownDetail(fallback typeFallback) string {
	switch {
	case fallback.Unread:
		return "пакет с изменённым типом не удалось прочитать, досягаемость не проверена"
	case fallback.Unresolved:
		return "не удалось собрать путь импорта изменённого типа, досягаемость не проверена"
	default:
		return "часть патча меняет тип без вызовов, но другой изменённый тип назвать не удалось, досягаемость не проверена"
	}
}
