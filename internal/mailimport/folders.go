package mailimport

import "strings"

// duplicativeVirtualAttrs are special-use folders whose contents mirror messages
// already filed in real folders — importing them double-files everything. These
// are Gmail's virtual labels surfaced over IMAP: \All ("All Mail"), \Important,
// and \Flagged ("Starred"). An import skips them.
var duplicativeVirtualAttrs = map[string]bool{
	"\\all":       true,
	"\\important": true,
	"\\flagged":   true,
}

// IsDuplicativeVirtual reports a folder that duplicates other folders' messages
// (Gmail All Mail / Important / Starred) and should be skipped during import.
func (f Folder) IsDuplicativeVirtual() bool {
	for _, a := range f.Attrs {
		if duplicativeVirtualAttrs[strings.ToLower(a)] {
			return true
		}
	}
	return false
}

// canonical special-use destination folder names. These match the auto-created
// \Sent/\Drafts/\Junk/\Trash/\Archive mailboxes in the Vectis Dovecot namespace
// (see dovecot.conf), so flagged source folders land in the right place even when
// their names differ (e.g. Gmail's "[Gmail]/Sent Mail" → "Sent").
var specialUseDest = map[string]string{
	"\\sent":    "Sent",
	"\\drafts":  "Drafts",
	"\\junk":    "Junk",
	"\\trash":   "Trash",
	"\\archive": "Archive",
}

// MapFolder maps a source folder to its destination folder name:
//   - INBOX is preserved verbatim.
//   - A folder carrying a recognised special-use attribute maps to the canonical
//     Vectis name for that role (so Sent/Drafts/Junk/Trash/Archive consolidate).
//   - Otherwise the source hierarchy delimiter is normalised to the destination
//     separator and the name is passed through.
//
// Note: Gmail's "\All"/"\Important" virtual folders are NOT special-cased here —
// importing All Mail duplicates messages already filed elsewhere. That trade-off
// is left for Phase 5 real-data hardening.
func MapFolder(f Folder, destSep string) string {
	if strings.EqualFold(f.Name, "INBOX") {
		return "INBOX"
	}
	for _, attr := range f.Attrs {
		if dest, ok := specialUseDest[strings.ToLower(attr)]; ok {
			return dest
		}
	}
	name := f.Name
	if f.Delim != "" && f.Delim != destSep {
		name = strings.ReplaceAll(name, f.Delim, destSep)
	}
	return name
}
