package scan

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"cve-patch-viewer/internal/applicability/task"
)

func TestPatchFullyAppliedRequiresEveryHunk(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"fixed\"\n}\n")
	file := task.PatchFile{Filename: rel, Patch: "" +
		"@@ -1,3 +1,3 @@\n" +
		" func HostID() string {\n" +
		"-\treturn \"vuln\"\n" +
		"+\treturn \"fixed\"\n" +
		" }\n"}
	match := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	if !patchFullyApplied(root, []task.PatchFile{file}, match) {
		t.Fatal("fixed file should count as applied")
	}

	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"vuln\"\n}\n")
	if patchFullyApplied(root, []task.PatchFile{file}, match) {
		t.Fatal("old code must stay applicable")
	}

	mustWrite(t, filepath.Join(root, rel), "func Other() string {\n\treturn \"old\"\n}\nfunc Other() string {\n\treturn \"fixed\"\n}\n")
	fileBoth := task.PatchFile{Filename: rel, Patch: "" +
		"@@ -1,3 +1,3 @@\n" +
		" func Other() string {\n" +
		"-\treturn \"old\"\n" +
		"+\treturn \"fixed\"\n" +
		" }\n"}
	if !patchFullyApplied(root, []task.PatchFile{fileBoth}, match) {
		t.Fatal("new code in the file is enough; another old copy does not cancel the hunk")
	}
}

func TestHunkIgnoresIndentCommentsAndBlankLines(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	match := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	diff := "" +
		"@@ -4,3 +4,3 @@\n" +
		" \tif err != nil {\n" +
		"-\t\treturn err\n" +
		"+\t\treturn nil // patched\n" +
		" \t}\n"
	// The fix is in place. Indent is deeper, the comment is absent, line
	// endings are CRLF, and another function still has the old return.
	body := strings.Join([]string{
		"package pkg",
		"",
		"func Handle() error {",
		"\t\tif err != nil {",
		"\t\t\treturn nil",
		"\t\t}",
		"\t\treturn nil",
		"}",
		"",
		"func Other() error {",
		"\tif err != nil {",
		"\t\treturn err",
		"\t}",
		"\treturn nil",
		"}",
		"",
	}, "\r\n")
	mustWrite(t, filepath.Join(root, rel), body)
	status, line := assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "full" {
		t.Fatal(status, line)
	}

	spaced := "" +
		"@@ -4,3 +4,3 @@\n" +
		"     if err != nil {\n" +
		"-        return err\n" +
		"+        return nil\n" +
		"     }\n"
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: spaced}, match)
	if status != "full" {
		t.Fatal(status, line)
	}

	withURL := "" +
		"@@ -1,3 +1,3 @@\n" +
		" func Host() string {\n" +
		"-\treturn \"vuln\"\n" +
		"+\treturn \"http://fixed\"\n" +
		" }\n"
	mustWrite(t, filepath.Join(root, rel), "func Host() string {\n\treturn \"http://fixed\" /* done */\n}\n")
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: withURL}, match)
	if status != "full" {
		t.Fatal(status, line)
	}

	// A real statement between the new lines is a different change.
	split := "" +
		"@@ -1,2 +1,3 @@\n" +
		" func Host() string {\n" +
		"+\tlog()\n" +
		"+\treturn \"http://fixed\"\n" +
		" }\n"
	mustWrite(t, filepath.Join(root, rel), "func Host() string {\n\tlog()\n\tfmt.Println()\n\treturn \"http://fixed\"\n}\n")
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: split}, match)
	if status != "partial" || !strings.Contains(line, "0 из 1") {
		t.Fatal(status, line)
	}

	// Comment and blank line between the added lines still match.
	mustWrite(t, filepath.Join(root, rel), "func Host() string {\n\tlog()\n\n\t// kept\n\treturn \"http://fixed\"\n}\n")
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: split}, match)
	if status != "full" {
		t.Fatal(status, line)
	}
}

func TestLaterCodeAfterThePatchDoesNotHideIt(t *testing.T) {
	root := t.TempDir()
	rel := "internal/envconfig/envconfig.go"
	match := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	diff := "" +
		"@@ -141,6 +141,17 @@ var (\n" +
		" \t// release.\n" +
		" \tEnableHTTPFramerReadBufferPooling = boolFromEnv(\"GRPC_GO_EXPERIMENTAL_HTTP_FRAMER_READ_BUFFER_POOLING\", true)\n" +
		"+\n" +
		"+	// ControlBufferThrottleLimit is the maximum number of control frames that can\n" +
		"+	// be queued before throttling is applied.\n" +
		"+	//\n" +
		"+	// TODO: Remove this env var once v1.83.0 is release.\n" +
		"+	ControlBufferThrottleLimit = uint64FromEnv(\"GRPC_GO_EXPERIMENTAL_CONTROL_BUFFER_THROTTLE_LIMIT\", 100, 1, 10000)\n" +
		" )\n" +
		" \n" +
		" func boolFromEnv(envVar string, def bool) bool {\n"
	// The variable from the patch is present. A later variable was added in
	// the same block, and the comment says "released" rather than "release".
	body := "" +
		"var (\n" +
		"\tEnableHTTPFramerReadBufferPooling = boolFromEnv(\"GRPC_GO_EXPERIMENTAL_HTTP_FRAMER_READ_BUFFER_POOLING\", true)\n" +
		"\n" +
		"\t// ControlBufferThrottleLimit is the maximum number of control frames that can\n" +
		"\t// be queued before throttling is applied.\n" +
		"\t//\n" +
		"\t// TODO: Remove this env var once v1.83.0 is released.\n" +
		"\tControlBufferThrottleLimit = uint64FromEnv(\"GRPC_GO_EXPERIMENTAL_CONTROL_BUFFER_THROTTLE_LIMIT\", 100, 1, 10000)\n" +
		"\n" +
		"\tEnableReceiveBufferCompaction = boolFromEnv(\"GRPC_GO_EXPERIMENTAL_ENABLE_RECEIVE_BUFFER_COMPACTION\", true)\n" +
		")\n" +
		"\n" +
		"func boolFromEnv(envVar string, def bool) bool {\n" +
		"\treturn true\n" +
		"}\n"
	mustWrite(t, filepath.Join(root, rel), body)
	status, line := assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "full" {
		t.Fatal(status, line)
	}

	// The added line itself is missing. Later code must not count as the patch.
	missing := strings.Replace(body, "\tControlBufferThrottleLimit = uint64FromEnv(\"GRPC_GO_EXPERIMENTAL_CONTROL_BUFFER_THROTTLE_LIMIT\", 100, 1, 10000)\n", "", 1)
	mustWrite(t, filepath.Join(root, rel), missing)
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "partial" || !strings.Contains(line, "0 из 1") {
		t.Fatal(status, line)
	}
}

func TestShortAdditionNeedsNearbyContext(t *testing.T) {
	root := t.TempDir()
	rel := "fse/compress.go"
	match := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	diff := "" +
		"@@ -10,7 +10,8 @@ func (s *Scratch) validateNorm() {\n" +
		" \t\tif v >= 0 {\n" +
		" \t\t\ttotal += int(v)\n" +
		" \t\t} else {\n" +
		"-\t\t\ttotal -= int(v)\n" +
		"+\t\t\t// -1 takes one cell. Adding -v would let a wrapped -32768 pass.\n" +
		"+\t\t\ttotal++\n" +
		" \t\t}\n" +
		" \t}\n"
	// The fix is not in validateNorm. The same total++ already lives in another function.
	body := "" +
		"func (s *Scratch) validateNorm() {\n" +
		"\tvar total int\n" +
		"\tfor _, v := range s.norm[:s.symbolLen] {\n" +
		"\t\tif v >= 0 {\n" +
		"\t\t\ttotal += int(v)\n" +
		"\t\t} else {\n" +
		"\t\t\ttotal -= int(v)\n" +
		"\t\t}\n" +
		"\t}\n" +
		"}\n" +
		"\n" +
		"func (s *Scratch) buildCTable() {\n" +
		"\tsymbolTT[i].deltaFindState = int32(total - 1)\n" +
		"\ttotal++\n" +
		"}\n"
	mustWrite(t, filepath.Join(root, rel), body)
	status, line := assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "partial" || !strings.Contains(line, "0 из 1") {
		t.Fatal(status, line)
	}

	// The new line is in the else, and the old line is still beside it.
	kept := strings.Replace(body, "\t\t\ttotal -= int(v)\n", "\t\t\ttotal -= int(v)\n\t\t\ttotal++\n", 1)
	mustWrite(t, filepath.Join(root, rel), kept)
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "partial" || !strings.Contains(line, "0 из 1") {
		t.Fatal(status, line)
	}

	// The old line is gone from that else. The other total++ does not matter.
	fixed := strings.Replace(body, "\t\t\ttotal -= int(v)\n", "\t\t\ttotal++\n", 1)
	mustWrite(t, filepath.Join(root, rel), fixed)
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "full" {
		t.Fatal(status, line)
	}
}

func TestContextMayDriftByThreeLines(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	match := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	diff := "" +
		"@@ -1,3 +1,4 @@\n" +
		" func before() {\n" +
		"+	added()\n" +
		" }\n" +
		" func after() {\n"
	between := func(n int) string {
		var b strings.Builder
		b.WriteString("func before() {\n\tadded()\n")
		for i := 0; i < n; i++ {
			b.WriteString("\textra()\n")
		}
		b.WriteString("}\nfunc after() {\n}\n")
		return b.String()
	}
	mustWrite(t, filepath.Join(root, rel), between(3))
	status, line := assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "full" {
		t.Fatal(status, line)
	}
	mustWrite(t, filepath.Join(root, rel), between(4))
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "partial" || !strings.Contains(line, "0 из 1") {
		t.Fatal(status, line)
	}

	// Indent-only change is the same code and still counts as applied.
	indent := "" +
		"@@ -1,3 +1,3 @@\n" +
		" func f() {\n" +
		"-\treturn nil\n" +
		"+\t\treturn nil\n" +
		" }\n"
	mustWrite(t, filepath.Join(root, rel), "func f() {\n\t\treturn nil\n}\n")
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: indent}, match)
	if status != "full" {
		t.Fatal(status, line)
	}
}

func TestEditOfMissingFuncDoesNotCount(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	match := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	diff := "" +
		"@@ -4,3 +4,3 @@ func HostID() string {\n" +
		" func HostID() string {\n" +
		"-\treturn \"vuln\"\n" +
		"+\treturn \"fixed\"\n" +
		" }\n" +
		"@@ -20,3 +20,3 @@ func Gone() {\n" +
		" func Gone() {\n" +
		"-\tuse()\n" +
		"+\tavoid()\n" +
		" }\n"
	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"fixed\"\n}\n")
	status, line := assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "full" || !strings.Contains(line, "Gone") {
		t.Fatal(status, line)
	}

	onlyGone := "" +
		"@@ -20,3 +20,3 @@ func Gone() {\n" +
		" func Gone() {\n" +
		"-\tuse()\n" +
		"+\tavoid()\n" +
		" }\n"
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: onlyGone}, match)
	if status != "nofunc" {
		t.Fatal(status, line)
	}

	// Reset on another type is not the method the hunk edits.
	method := "" +
		"@@ -8,3 +8,3 @@ func (sr *snappyReader) Reset(r io.Reader) error {\n" +
		" func (sr *snappyReader) Reset(r io.Reader) error {\n" +
		"-\treturn err\n" +
		"+\treturn nil\n" +
		" }\n"
	mustWrite(t, filepath.Join(root, rel), "func (r *otherReader) Reset(r io.Reader) error {\n\treturn nil\n}\n")
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: method}, match)
	if status != "nofunc" || !strings.Contains(line, "snappyReader.Reset") {
		t.Fatal(status, line)
	}

	// A function added from scratch still has to be there.
	created := "" +
		"@@ -1,3 +1,6 @@ func HostID() string {\n" +
		" func HostID() string {\n" +
		" \treturn \"fixed\"\n" +
		" }\n" +
		"+func Guard() {}\n"
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: created}, match)
	if status != "partial" || !strings.Contains(line, "0 из 1") {
		t.Fatal(status, line)
	}
	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"fixed\"\n}\nfunc Guard() {}\n")
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: created}, match)
	if status != "full" {
		t.Fatal(status, line)
	}
}

func TestEditUnderLaterMissingFuncDoesNotCount(t *testing.T) {
	root := t.TempDir()
	rel := "lib/backup/fslocal/fslocal.go"
	match := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	diff := "" +
		"@@ -129,6 +129,10 @@ func (fs *FS) NewReadCloser(p common.Part) (io.ReadCloser, error) {\n" +
		" // comment\n" +
		" func (fs *FS) NewDirectWriteCloser(p common.Part) (io.WriteCloser, error) {\n" +
		"+	if !p.IsLocalPathInsideDir(fs.Dir) {\n" +
		"+		logger.Fatalf(\"outside\")\n" +
		"+	}\n" +
		"+\n" +
		" \tpath := fs.writePath(p)\n"
	body := "func (fs *FS) NewReadCloser(p common.Part) (io.ReadCloser, error) {\n\treturn nil\n}\n"
	mustWrite(t, filepath.Join(root, rel), body)
	status, line := assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "nofunc" || !strings.Contains(line, "FS.NewDirectWriteCloser") {
		t.Fatal(status, line)
	}

	// Header only, no func line in the hunk: the missing name is still the header.
	headerOnly := "" +
		"@@ func Gone() {\n" +
		"-\tuse()\n" +
		"+\tavoid()\n"
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: headerOnly}, match)
	if status != "nofunc" || !strings.Contains(line, "Gone") {
		t.Fatal(status, line)
	}

	withGuard := "func (fs *FS) NewReadCloser(p common.Part) (io.ReadCloser, error) {\n\treturn nil\n}\n\n" +
		"func (fs *FS) NewDirectWriteCloser(p common.Part) (io.WriteCloser, error) {\n" +
		"\tif !p.IsLocalPathInsideDir(fs.Dir) {\n\t\tlogger.Fatalf(\"outside\")\n\t}\n" +
		"\tpath := fs.writePath(p)\n\treturn nil\n}\n"
	mustWrite(t, filepath.Join(root, rel), withGuard)
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "full" {
		t.Fatal(status, line)
	}

	// An edit of the function that exists stays; the lines under the missing one do not.
	mixed := "" +
		"@@ func (fs *FS) NewReadCloser(p common.Part) (io.ReadCloser, error) {\n" +
		" func (fs *FS) NewReadCloser(p common.Part) (io.ReadCloser, error) {\n" +
		"+	limit()\n" +
		" }\n" +
		" func (fs *FS) NewDirectWriteCloser(p common.Part) (io.WriteCloser, error) {\n" +
		"+	guard()\n" +
		" }\n"
	mustWrite(t, filepath.Join(root, rel), "func (fs *FS) NewReadCloser(p common.Part) (io.ReadCloser, error) {\n\tlimit()\n}\n")
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: mixed}, match)
	if status != "full" || !strings.Contains(line, "FS.NewDirectWriteCloser") {
		t.Fatal(status, line)
	}
}

func TestSeparateAdditionsIgnoreNeighborOrder(t *testing.T) {
	root := t.TempDir()
	rel := "lib/protoparser/protoparserutil/compress_reader.go"
	match := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	diff := "" +
		"@@ -5,17 +5,24 @@ import (\n" +
		" \t\"io\"\n" +
		" \t\"sync\"\n" +
		" \n" +
		"- \t\"github.com/golang/snappy\"\n" +
		" \t\"github.com/klauspost/compress/gzip\"\n" +
		" \t\"github.com/klauspost/compress/zlib\"\n" +
		" \n" +
		" \t\"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil\"\n" +
		"+ \t\"github.com/VictoriaMetrics/VictoriaMetrics/lib/encoding/snappy\"\n" +
		" \t\"github.com/VictoriaMetrics/VictoriaMetrics/lib/encoding/zstd\"\n" +
		" \t\"github.com/VictoriaMetrics/VictoriaMetrics/lib/flagutil\"\n" +
		" )\n" +
		" \n" +
		"+// limit to 56MB\n" +
		"+const maxSnappyBlockSize = 56_000_000\n" +
		"+\n" +
		" // ReadUncompressedData reads uncompressed data.\n"
	// gofmt put the new import where github.com/golang/snappy used to be.
	body := "" +
		"import (\n" +
		"\t\"io\"\n" +
		"\t\"sync\"\n" +
		"\n" +
		"\t\"github.com/VictoriaMetrics/VictoriaMetrics/lib/encoding/snappy\"\n" +
		"\t\"github.com/klauspost/compress/gzip\"\n" +
		"\t\"github.com/klauspost/compress/zlib\"\n" +
		"\n" +
		"\t\"github.com/VictoriaMetrics/VictoriaMetrics/lib/bytesutil\"\n" +
		"\t\"github.com/VictoriaMetrics/VictoriaMetrics/lib/encoding/zstd\"\n" +
		"\t\"github.com/VictoriaMetrics/VictoriaMetrics/lib/flagutil\"\n" +
		")\n" +
		"\n" +
		"const maxSnappyBlockSize = 56_000_000\n" +
		"\n" +
		"// ReadUncompressedData reads uncompressed data.\n" +
		"func ReadUncompressedData() {}\n"
	mustWrite(t, filepath.Join(root, rel), body)
	status, line := assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "full" {
		t.Fatal(status, line)
	}

	// The new import is present, but the old one was left in place.
	kept := strings.Replace(body, "\"github.com/klauspost/compress/gzip\"", "\"github.com/golang/snappy\"\n\t\"github.com/klauspost/compress/gzip\"", 1)
	mustWrite(t, filepath.Join(root, rel), kept)
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "partial" || !strings.Contains(line, "0 из 1") {
		t.Fatal(status, line)
	}

	// The constant never arrived. The moved import alone is not the whole hunk.
	missingConst := strings.Replace(body, "const maxSnappyBlockSize = 56_000_000\n", "", 1)
	mustWrite(t, filepath.Join(root, rel), missingConst)
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "partial" || !strings.Contains(line, "0 из 1") {
		t.Fatal(status, line)
	}
}

func TestOrdinaryRemovedLineInAnotherFunctionDoesNotCancel(t *testing.T) {
	root := t.TempDir()
	rel := "internal/transport/controlbuf.go"
	match := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	diff := "" +
		"@@ func (l *loopyWriter) registerStreamHandler\n" +
		" func (l *loopyWriter) registerStreamHandler() {\n" +
		" \tstr := &outStream{\n" +
		"- \t\tid: h.streamID,\n" +
		"+ \t\tid: hdr.streamID,\n" +
		" \t\tstate: empty,\n" +
		"- \t\twq: h.wq,\n" +
		"+ \t\twq: hdr.wq,\n" +
		" \t}\n" +
		"+ \treturn nil\n" +
		" }\n"
	// The same short fields and return nil stay in another function.
	body := "" +
		"func (l *loopyWriter) registerStreamHandler() {\n" +
		"\tstr := &outStream{\n" +
		"\t\tid: h.streamID,\n" +
		"\t\tstate: empty,\n" +
		"\t\twq: h.wq,\n" +
		"\t}\n" +
		"\treturn nil\n" +
		"}\n" +
		"func (l *loopyWriter) clientHeaderHandler() {\n" +
		"\tstr := &outStream{\n" +
		"\t\tid: hdr.streamID,\n" +
		"\t\tstate: empty,\n" +
		"\t\twq: hdr.wq,\n" +
		"\t}\n" +
		"\treturn nil\n" +
		"}\n"
	mustWrite(t, filepath.Join(root, rel), body)
	status, line := assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "full" {
		t.Fatal(status, line)
	}

	// The new field is in place, and the old one is still next to it.
	beside := strings.Replace(body, "\t\tid: hdr.streamID,\n", "\t\tid: hdr.streamID,\n\t\tid: h.streamID,\n", 1)
	mustWrite(t, filepath.Join(root, rel), beside)
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "partial" || !strings.Contains(line, "0 из 1") {
		t.Fatal(status, line)
	}
}

func TestLongRemovedLineStillCancelsASplitHunk(t *testing.T) {
	root := t.TempDir()
	rel := "internal/transport/controlbuf.go"
	match := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	diff := "" +
		"@@ func Foo\n" +
		" context()\n" +
		"- if err := uniqueLongCondition(streamID, quota, peer); err != nil {\n" +
		"+ if err := uniqueLongCondition(streamID, quota, peerChecked); err != nil {\n" +
		" next()\n" +
		"+ addedOtherCall()\n" +
		" more()\n"
	body := "" +
		"func Foo() {\n" +
		"\tcontext()\n" +
		"\tif err := uniqueLongCondition(streamID, quota, peerChecked); err != nil {\n" +
		"\t\tnext()\n" +
		"\t\taddedOtherCall()\n" +
		"\t\tmore()\n" +
		"\t}\n" +
		"}\n" +
		"func Other() {\n" +
		"\tif err := uniqueLongCondition(streamID, quota, peer); err != nil {\n" +
		"\t\treturn\n" +
		"\t}\n" +
		"}\n"
	mustWrite(t, filepath.Join(root, rel), body)
	status, line := assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "partial" || !strings.Contains(line, "0 из 1") {
		t.Fatal(status, line)
	}

	gone := strings.Replace(body, "\tif err := uniqueLongCondition(streamID, quota, peer); err != nil {\n\t\treturn\n\t}\n", "", 1)
	mustWrite(t, filepath.Join(root, rel), gone)
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "full" {
		t.Fatal(status, line)
	}
}

func TestLineTailMayDifferAfterTheEdit(t *testing.T) {
	root := t.TempDir()
	rel := "src/net/http/server.go"
	match := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	diff := "" +
		"@@ -2164,7 +2168,7 @@\n" +
		" \t\t\tif !w.shouldReuseConnection() {\n" +
		"-\t\t\t\tif w.requestBodyLimitHit || !w.reqBody.consumedEntireBody() {\n" +
		"+\t\t\t\tif w.requestBodyLimitHit.Load() || !w.reqBody.consumedEntireBody() {\n" +
		" \t\t\t\t\tc.closeWriteAndWait()\n" +
		" \t\t\t\t}\n" +
		" \t\t\t\treturn\n"
	// The release branch already renamed the tail. The edit .Load() is in place.
	fixed := "" +
		"func (w *response) writeHeader() {\n" +
		"\tif w.requestBodyLimitHit.Load() {\n" +
		"\t\tw.closeAfterReply = true\n" +
		"\t}\n" +
		"}\n" +
		"func (w *response) shouldReuseConnection() bool {\n" +
		"\tif w.closeAfterReply || w.requestBodyLimitHit.Load() {\n" +
		"\t\treturn false\n" +
		"\t}\n" +
		"}\n" +
		"func (c *conn) serve() {\n" +
		"\tif !w.shouldReuseConnection() {\n" +
		"\t\tif w.requestBodyLimitHit.Load() || w.closedRequestBodyEarly() {\n" +
		"\t\t\tc.closeWriteAndWait()\n" +
		"\t\t}\n" +
		"\t\treturn\n" +
		"\t}\n" +
		"}\n"
	mustWrite(t, filepath.Join(root, rel), fixed)
	status, line := assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "full" {
		t.Fatal(status, line)
	}

	// Same helpers, but the closeWrite line never received .Load().
	unfixed := strings.Replace(fixed, "w.requestBodyLimitHit.Load() || w.closedRequestBodyEarly()", "w.requestBodyLimitHit || w.closedRequestBodyEarly()", 1)
	mustWrite(t, filepath.Join(root, rel), unfixed)
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "partial" || !strings.Contains(line, "0 из 1") {
		t.Fatal(status, line)
	}
}

func TestPureDeletionUsesRemovedCode(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	match := []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}
	diff := "" +
		"@@ -1,4 +1,3 @@\n" +
		" func Host() {\n" +
		"-\tdebug()\n" +
		" \twork()\n" +
		" }\n"
	mustWrite(t, filepath.Join(root, rel), "func Host() {\n\twork()\n}\n")
	status, line := assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "full" {
		t.Fatal(status, line)
	}
	mustWrite(t, filepath.Join(root, rel), "func Host() {\n\tdebug()\n\twork()\n}\n")
	status, line = assessPatchFile(root, task.PatchFile{Filename: rel, Patch: diff}, match)
	if status != "partial" {
		t.Fatal(status, line)
	}
}

func TestPatchAppliedOnlyWhenReachable(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"fixed\"\n}\n")
	files := []task.PatchFile{{Filename: rel, Patch: "" +
		"@@ -1,3 +1,3 @@\n" +
		" func HostID() string {\n" +
		"-\treturn \"vuln\"\n" +
		"+\treturn \"fixed\"\n" +
		" }\n"}}
	report := task.Report{PatchFiles: []task.PatchFileMatch{{Filename: rel, Found: true, Path: "./" + rel}}}
	if note := noteAppliedPatch(root, files, &report); note != "" || report.PatchApplied != nil {
		t.Fatal("unreachable patch must stay applicable")
	}
	if report.PatchCheck == nil || report.PatchCheck.Ran || !strings.Contains(report.PatchCheck.Section(), "не проводилась") {
		t.Fatalf("%+v", report.PatchCheck)
	}
	report.Narrative = "журнал анализа"
	if !strings.Contains(report.PublicText(), "Проверка применения патча") || !strings.Contains(report.PublicText(), "журнал анализа") {
		t.Fatal(report.PublicText())
	}
	yes := true
	report.Reach = &task.ReachReport{Reachable: &yes}
	if note := noteAppliedPatch(root, files, &report); note == "" || report.PatchApplied == nil || !report.PatchApplied.Applied {
		t.Fatal(note, report.PatchApplied)
	}
	if decideApplicability(report, "") != task.NotApplicable {
		t.Fatal(decideApplicability(report, ""))
	}
	if report.PatchCheck == nil || report.PatchCheck.Outcome != task.PatchCheckFull || !strings.Contains(report.PatchCheck.Section(), "неприменима") {
		t.Fatal(report.PatchCheck.Section())
	}

	report.Reach = &task.ReachReport{Reachable: &yes}
	report.PatchApplied = nil
	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"vuln\"\n}\n")
	if note := noteAppliedPatch(root, files, &report); note != "" || report.PatchApplied != nil {
		t.Fatal("partial patch must stay applicable")
	}
	if report.PatchCheck.Outcome != task.PatchCheckPartial || !strings.Contains(report.PatchCheck.Section(), "не целиком") {
		t.Fatal(report.PatchCheck.Section())
	}
}

func TestDeletedFileCountsOnlyWhenGone(t *testing.T) {
	root := t.TempDir()
	diff := "--- a/old.go\n+++ /dev/null\n@@ -1 +0,0 @@\n-package old\n"
	if !patchFullyApplied(root, []task.PatchFile{{Filename: "old.go", Patch: diff}}, []task.PatchFileMatch{{Filename: "old.go", Found: false}}) {
		t.Fatal("missing deleted file is applied")
	}
	mustWrite(t, filepath.Join(root, "old.go"), "package old\n")
	if patchFullyApplied(root, []task.PatchFile{{Filename: "old.go", Patch: diff}}, []task.PatchFileMatch{{Filename: "old.go", Found: true, Path: "./old.go"}}) {
		t.Fatal("deleted file still present")
	}
}

func TestMarkdownDoesNotBlockAFullPatch(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"fixed\"\n}\n")
	mustWrite(t, filepath.Join(root, "CHANGELOG.md"), "unrelated\n")
	code := task.PatchFile{Filename: rel, Patch: "" +
		"@@ -1,3 +1,3 @@\n" +
		" func HostID() string {\n" +
		"-\treturn \"vuln\"\n" +
		"+\treturn \"fixed\"\n" +
		" }\n"}
	md := task.PatchFile{Filename: "CHANGELOG.MD", Patch: "" +
		"@@ -1 +1 @@\n" +
		"-old changelog\n" +
		"+new changelog\n"}
	matches := []task.PatchFileMatch{
		{Filename: rel, Found: true, Path: "./" + rel},
		{Filename: "CHANGELOG.MD", Found: true, Path: "./CHANGELOG.md"},
	}
	if !patchFullyApplied(root, []task.PatchFile{code, md}, matches) {
		t.Fatal("changelog must not keep an otherwise applied patch open")
	}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	if note := noteAppliedPatch(root, []task.PatchFile{code, md}, &report); note == "" || report.PatchApplied == nil || !report.PatchApplied.Applied {
		t.Fatal(note, report.PatchCheck)
	}
	if report.PatchCheck.Outcome != task.PatchCheckFull || !strings.Contains(report.PatchCheck.Section(), "markdown") {
		t.Fatal(report.PatchCheck.Section())
	}
	if decideApplicability(report, "") != task.NotApplicable {
		t.Fatal(decideApplicability(report, ""))
	}
}

func TestMarkdownOnlyPatchDoesNotCountAsApplied(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "CHANGELOG.md"), "new changelog\n")
	md := task.PatchFile{Filename: "docs/CHANGELOG.md", Patch: "" +
		"@@ -1 +1 @@\n" +
		"-old changelog\n" +
		"+new changelog\n"}
	matches := []task.PatchFileMatch{{Filename: "docs/CHANGELOG.md", Found: true, Path: "./CHANGELOG.md"}}
	if patchFullyApplied(root, []task.PatchFile{md}, matches) {
		t.Fatal("a markdown-only patch is not a code fix")
	}
	report := task.Report{PatchFiles: matches}
	if note := noteAppliedPatch(root, []task.PatchFile{md}, &report); note != "" || report.PatchApplied != nil {
		t.Fatal(note, report.PatchApplied)
	}
	if report.PatchCheck == nil || report.PatchCheck.Ran || report.PatchCheck.Outcome != task.PatchCheckNotRun {
		t.Fatalf("%+v", report.PatchCheck)
	}
	if !strings.Contains(report.PatchCheck.Section(), "только markdown") {
		t.Fatal(report.PatchCheck.Section())
	}
	if decideApplicability(report, "") == task.NotApplicable {
		t.Fatal("markdown must not force not applicable")
	}
}

func appliedHunk(name, body string) task.PatchFile {
	return task.PatchFile{Filename: name, Patch: "" +
		"@@ -1,3 +1,3 @@\n" +
		" func HostID() string {\n" +
		"-\treturn \"vuln\"\n" +
		"+\treturn \"" + body + "\"\n" +
		" }\n"}
}

func TestTestFileDoesNotBlockFullPatch(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"fixed\"\n}\n")
	code := appliedHunk(rel, "fixed")
	testFile := appliedHunk("pkg/id_test.go", "fixed")
	matches := []task.PatchFileMatch{
		{Filename: rel, Found: true, Path: "./" + rel},
		{Filename: "pkg/id_test.go", Found: false},
	}
	if !patchFullyApplied(root, []task.PatchFile{code, testFile}, matches) {
		t.Fatal("a missing test file must not keep the patch open")
	}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	if note := noteAppliedPatch(root, []task.PatchFile{code, testFile}, &report); note == "" || report.PatchApplied == nil || !report.PatchApplied.Applied {
		t.Fatal(note, report.PatchCheck)
	}
	if report.PatchCheck.Outcome != task.PatchCheckFull || len(report.PatchCheck.NotApplied) != 0 {
		t.Fatalf("%+v", report.PatchCheck)
	}
	if !strings.Contains(report.PatchCheck.Section(), "Тестовые файлы") {
		t.Fatal(report.PatchCheck.Section())
	}
}

func TestPartialPatchNamesOnlyUnappliedCodeFiles(t *testing.T) {
	root := t.TempDir()
	fixedRel := "pkg/id.go"
	openRel := "pkg/other.go"
	mustWrite(t, filepath.Join(root, fixedRel), "func HostID() string {\n\treturn \"fixed\"\n}\n")
	mustWrite(t, filepath.Join(root, openRel), "func HostID() string {\n\treturn \"vuln\"\n}\n")
	files := []task.PatchFile{
		appliedHunk(fixedRel, "fixed"),
		appliedHunk(openRel, "fixed"),
		appliedHunk("pkg/other_test.go", "fixed"),
	}
	matches := []task.PatchFileMatch{
		{Filename: fixedRel, Found: true, Path: "./" + fixedRel},
		{Filename: openRel, Found: true, Path: "./" + openRel},
		{Filename: "pkg/other_test.go", Found: false},
	}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	if note := noteAppliedPatch(root, files, &report); note != "" || report.PatchApplied != nil {
		t.Fatal(note, report.PatchApplied)
	}
	if report.PatchCheck.Outcome != task.PatchCheckPartial {
		t.Fatal(report.PatchCheck.Outcome)
	}
	if strings.Join(report.PatchCheck.NotApplied, ",") != openRel {
		t.Fatal(report.PatchCheck.NotApplied)
	}
	got := withPartialPatchNote("Уязвимость применима к компоненту.", report)
	want := "Уязвимость применима к компоненту. Патч частично применен, но в этих файлах патч не применен - pkg/other.go."
	if got != want {
		t.Fatal(got)
	}
	if strings.Contains(got, "other_test.go") {
		t.Fatal(got)
	}
}

func TestMissingEditDoesNotBlockFullPatch(t *testing.T) {
	root := t.TempDir()
	rel := "pkg/id.go"
	mustWrite(t, filepath.Join(root, rel), "func HostID() string {\n\treturn \"fixed\"\n}\n")
	code := appliedHunk(rel, "fixed")
	edit := appliedHunk("sdk/internal/attrnorm/truncate.go", "fixed")
	created := task.PatchFile{Filename: "trace/new.go", Patch: "" +
		"--- /dev/null\n" +
		"+++ b/trace/new.go\n" +
		"@@ -0,0 +1,3 @@\n" +
		"+package trace\n" +
		"+\n" +
		"+func New() {}\n"}
	matches := []task.PatchFileMatch{
		{Filename: rel, Found: true, Path: "./" + rel},
		{Filename: edit.Filename, Found: false},
	}
	if !patchFullyApplied(root, []task.PatchFile{code, edit}, matches) {
		t.Fatal("a missing edit of an existing file must not keep the patch open")
	}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	if note := noteAppliedPatch(root, []task.PatchFile{code, edit}, &report); note == "" || report.PatchApplied == nil || !report.PatchApplied.Applied {
		t.Fatal(note, report.PatchCheck)
	}
	if len(report.PatchCheck.NotApplied) != 0 || !strings.Contains(report.PatchCheck.Section(), "только правит") {
		t.Fatalf("%+v", report.PatchCheck)
	}

	matches = append(matches, task.PatchFileMatch{Filename: created.Filename, Found: false})
	if patchFullyApplied(root, []task.PatchFile{code, edit, created}, matches) {
		t.Fatal("a missing file created by the patch must keep it open")
	}
	report = task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	if note := noteAppliedPatch(root, []task.PatchFile{code, edit, created}, &report); note != "" || report.PatchApplied != nil {
		t.Fatal(note, report.PatchApplied)
	}
	if strings.Join(report.PatchCheck.NotApplied, ",") != created.Filename {
		t.Fatal(report.PatchCheck.NotApplied)
	}
}

func TestOnlyMissingEditsDoNotCountAsApplied(t *testing.T) {
	edit := appliedHunk("sdk/internal/attrnorm/truncate.go", "fixed")
	matches := []task.PatchFileMatch{{Filename: edit.Filename, Found: false}}
	if patchFullyApplied(t.TempDir(), []task.PatchFile{edit}, matches) {
		t.Fatal("nothing to compare")
	}
}

func TestNoAppliedFileSkipsPartialSentence(t *testing.T) {
	root := t.TempDir()
	first := "pkg/id.go"
	second := "pkg/other.go"
	mustWrite(t, filepath.Join(root, first), "func HostID() string {\n\treturn \"vuln\"\n}\n")
	mustWrite(t, filepath.Join(root, second), "func HostID() string {\n\treturn \"vuln\"\n}\n")
	files := []task.PatchFile{appliedHunk(first, "fixed"), appliedHunk(second, "fixed")}
	matches := []task.PatchFileMatch{
		{Filename: first, Found: true, Path: "./" + first},
		{Filename: second, Found: true, Path: "./" + second},
	}
	yes := true
	report := task.Report{PatchFiles: matches, Reach: &task.ReachReport{Reachable: &yes}}
	noteAppliedPatch(root, files, &report)
	if report.PatchCheck.Outcome != task.PatchCheckPartial || len(report.PatchCheck.NotApplied) != 0 {
		t.Fatalf("%+v", report.PatchCheck)
	}
	if got := withPartialPatchNote("Уязвимость применима.", report); got != "Уязвимость применима." {
		t.Fatal(got)
	}
}

func TestPartialNoteReachesTheVerdict(t *testing.T) {
	restore := stubModuleDeadcode(t, func(context.Context, string, bool) moduleDeadcode {
		return moduleDeadcode{Status: "ok"}
	})
	defer restore()

	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "go.mod"), "module example.com/alertmanager\n\nrequire go.opentelemetry.io/otel/sdk v1.43.0\n")
	fixed := "vendor/go.opentelemetry.io/otel/sdk/resource/host_id.go"
	open := "vendor/go.opentelemetry.io/otel/sdk/resource/other.go"
	mustWrite(t, filepath.Join(root, fixed), "package resource\n\nfunc HostID() string {\n\treturn \"fixed\"\n}\n")
	mustWrite(t, filepath.Join(root, open), "package resource\n\nfunc HostID() string {\n\treturn \"vuln\"\n}\n")
	got, err := Scan(context.Background(), Input{
		RepoPath:    root,
		CVEID:       "CVE-2026-24051",
		PackageName: "go.opentelemetry.io/otel/sdk",
	}, twoFilePatch{}, staticAI{})
	if err != nil {
		t.Fatal(err)
	}
	verdict := got[0].Verdict
	if !strings.Contains(verdict, "Патч частично применен, но в этих файлах патч не применен - sdk/resource/other.go.") {
		t.Fatal(verdict)
	}
	if strings.Contains(verdict, "_test.go") {
		t.Fatal(verdict)
	}
	if got[0].Applicability != task.Applicable {
		t.Fatal(got[0].Applicability)
	}
}

type twoFilePatch struct{}

func (twoFilePatch) Fetch(context.Context, string) (task.CVEPatch, error) {
	return task.CVEPatch{
		CVE: "CVE-2026-24051",
		Files: []task.PatchFile{
			appliedHunk("sdk/resource/host_id.go", "fixed"),
			appliedHunk("sdk/resource/other.go", "fixed"),
			appliedHunk("sdk/resource/host_id_test.go", "fixed"),
		},
	}, nil
}

func TestTestOnlyPatchIsNotApplied(t *testing.T) {
	root := t.TempDir()
	file := appliedHunk("pkg/id_test.go", "fixed")
	matches := []task.PatchFileMatch{{Filename: file.Filename, Found: true, Path: "./pkg/id_test.go"}}
	mustWrite(t, filepath.Join(root, "pkg/id_test.go"), "func HostID() string {\n\treturn \"fixed\"\n}\n")
	if patchFullyApplied(root, []task.PatchFile{file}, matches) {
		t.Fatal("tests alone are not a code fix")
	}
	report := task.Report{PatchFiles: matches}
	if note := noteAppliedPatch(root, []task.PatchFile{file}, &report); note != "" || report.PatchApplied != nil {
		t.Fatal(note)
	}
	if report.PatchCheck.Ran || report.PatchCheck.Outcome != task.PatchCheckNotRun {
		t.Fatalf("%+v", report.PatchCheck)
	}
}
