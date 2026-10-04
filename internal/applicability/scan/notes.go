package scan

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"cve-patch-viewer/internal/applicability/task"
)

const (
	devNotesPath     = "dapp/README.md"
	maxDevNotesBytes = 256 << 10
	maxDevNotesRunes = 6000
)

func loadDevNotes(repoPath string) (*task.DevNotes, error) {
	f, err := os.Open(filepath.Join(repoPath, filepath.FromSlash(devNotesPath)))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("dapp/README.md: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("dapp/README.md: %w", err)
	}
	if info.IsDir() {
		return nil, nil
	}
	body, err := io.ReadAll(io.LimitReader(f, maxDevNotesBytes+1))
	if err != nil {
		return nil, fmt.Errorf("dapp/README.md: %w", err)
	}
	notes := &task.DevNotes{Path: devNotesPath}
	if len(body) > maxDevNotesBytes {
		body = body[:maxDevNotesBytes]
		notes.Truncated = true
	}
	if bytes.IndexByte(body, 0) >= 0 {
		notes.Text = "(файл не текстовый)"
		return notes, nil
	}
	text := string(bytes.ToValidUTF8(body, nil))
	runes := []rune(text)
	if len(runes) > maxDevNotesRunes {
		text = string(runes[:maxDevNotesRunes])
		notes.Truncated = true
	}
	notes.Text = text
	return notes, nil
}

func attachNotes(results []task.ModuleResult, notes *task.DevNotes) {
	if notes == nil {
		return
	}
	fact := devNotesFact(notes)
	for i := range results {
		copied := *notes
		results[i].ReportMD.DevNotes = &copied
		if fact == "" {
			continue
		}
		results[i].Verdict = strings.TrimSpace(fact + " " + results[i].Verdict)
	}
}

func devNotesFact(n *task.DevNotes) string {
	if n == nil {
		return ""
	}
	if strings.TrimSpace(n.Text) == "" {
		return "Файл dapp/README.md есть, заметок в нём нет."
	}
	if n.Truncated {
		return "Заметки разработчиков прочитаны из dapp/README.md и обрезаны по размеру."
	}
	return "Заметки разработчиков прочитаны из dapp/README.md."
}
