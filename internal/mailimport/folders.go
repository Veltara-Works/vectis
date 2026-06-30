package mailimport

import (
	"strings"
	"unicode/utf8"
)

// maxFolderNameLen bounds a mapped destination folder name. Real IMAP/maildir
// names sit well under this; the cap stops an untrusted source server from
// driving Dovecot to create a pathologically long mailbox path.
const maxFolderNameLen = 255

// sanitizeFolderName makes a source-derived folder name safe to hand to the
// destination IMAP server / Dovecot maildir. We import FROM an untrusted IMAP
// server, so its folder names may carry control characters (incl. CR/LF),
// "."/".." path-traversal components, or unbounded length. go-imap quotes
// mailbox names, so this is defence in depth at the Dovecot/maildir boundary.
// destSep is the destination hierarchy separator; components are cleaned
// individually so a legitimate hierarchy is preserved. Returns "Imported" if
// nothing usable survives (so the message still lands somewhere).
func sanitizeFolderName(name, destSep string) string {
	// Strip control characters (< 0x20, incl. the CR/LF IMAP-injection vector)
	// and DEL (0x7f); keep everything else, including non-ASCII.
	var b strings.Builder
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	cleaned := b.String()

	// Drop empty / "." / ".." components so a name can't traverse the maildir.
	if destSep != "" {
		parts := strings.Split(cleaned, destSep)
		kept := parts[:0]
		for _, p := range parts {
			t := strings.TrimSpace(p)
			if t == "" || t == "." || t == ".." {
				continue
			}
			kept = append(kept, p)
		}
		cleaned = strings.Join(kept, destSep)
	}

	// Bound length, trimming back to a UTF-8 rune boundary and dropping any
	// dangling separator the truncation leaves behind.
	if len(cleaned) > maxFolderNameLen {
		cleaned = cleaned[:maxFolderNameLen]
		for len(cleaned) > 0 && !utf8.ValidString(cleaned) {
			cleaned = cleaned[:len(cleaned)-1]
		}
		if destSep != "" {
			cleaned = strings.TrimRight(cleaned, destSep)
		}
	}

	if cleaned == "" {
		return "Imported"
	}
	return cleaned
}

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
	// The source server is untrusted; sanitize before the name reaches Dovecot.
	// (INBOX and the special-use canonical names above are safe constants and
	// are returned before this point.)
	return sanitizeFolderName(name, destSep)
}
