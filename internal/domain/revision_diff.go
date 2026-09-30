package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// RevisionContentFingerprint returns a stable sha256 fingerprint of the
// immutable content of a stored zone revision. Entries are sorted before
// hashing so the fingerprint depends only on content, never on input order.
func RevisionContentFingerprint(revision ZoneRevision) string {
	entries := append([]ZoneEntry(nil), revision.Entries...)
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Owner != entries[j].Owner {
			return entries[i].Owner < entries[j].Owner
		}
		if entries[i].Type != entries[j].Type {
			return entries[i].Type < entries[j].Type
		}
		return entries[i].Value < entries[j].Value
	})
	payload, _ := json.Marshal(struct {
		Serial    uint32      `json:"serial"`
		Authority string      `json:"authority"`
		Entries   []ZoneEntry `json:"entries"`
	}{
		Serial:    revision.Serial,
		Authority: revision.Authority,
		Entries:   entries,
	})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// DiffRevisions compares the entries of a freshly written revision against the
// revision immediately preceding it. A nil previous marks the plan baseline:
// every entry of the current revision is reported as added. Entry identity is
// owner plus record type, so a changed value is reported as "changed".
// Entries are normalized and sorted by (owner, type, value) before storage;
// should a revision contain several values for the same owner and type, the
// largest value deterministically represents the record set.
func DiffRevisions(previous *ZoneRevision, current ZoneRevision) RevisionDiffSummary {
	summary := RevisionDiffSummary{
		Added:   []RevisionEntryChange{},
		Changed: []RevisionEntryChange{},
		Removed: []RevisionEntryChange{},
	}
	currentRecords := entryValues(current.Entries)
	if previous == nil {
		summary.Baseline = true
		for key, value := range currentRecords {
			summary.Added = append(summary.Added, RevisionEntryChange{
				Kind:  RevisionChangeAdded,
				Owner: key.owner,
				Type:  key.entryType,
				After: value,
			})
		}
		sortChanges(summary.Added)
		return summary
	}
	summary.PreviousRevisionID = previous.ID
	summary.PreviousSerial = previous.Serial
	previousRecords := entryValues(previous.Entries)
	for key, value := range currentRecords {
		prior, existed := previousRecords[key]
		switch {
		case !existed:
			summary.Added = append(summary.Added, RevisionEntryChange{
				Kind:  RevisionChangeAdded,
				Owner: key.owner,
				Type:  key.entryType,
				After: value,
			})
		case prior != value:
			summary.Changed = append(summary.Changed, RevisionEntryChange{
				Kind:   RevisionChangeChanged,
				Owner:  key.owner,
				Type:   key.entryType,
				Before: prior,
				After:  value,
			})
		}
	}
	for key, value := range previousRecords {
		if _, exists := currentRecords[key]; exists {
			continue
		}
		summary.Removed = append(summary.Removed, RevisionEntryChange{
			Kind:   RevisionChangeRemoved,
			Owner:  key.owner,
			Type:   key.entryType,
			Before: value,
		})
	}
	sortChanges(summary.Added)
	sortChanges(summary.Changed)
	sortChanges(summary.Removed)
	return summary
}

type entryKey struct {
	owner     string
	entryType EntryType
}

func entryValues(entries []ZoneEntry) map[entryKey]string {
	ordered := append([]ZoneEntry(nil), entries...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Owner != ordered[j].Owner {
			return ordered[i].Owner < ordered[j].Owner
		}
		if ordered[i].Type != ordered[j].Type {
			return ordered[i].Type < ordered[j].Type
		}
		return ordered[i].Value < ordered[j].Value
	})
	records := make(map[entryKey]string, len(ordered))
	for _, entry := range ordered {
		records[entryKey{owner: entry.Owner, entryType: entry.Type}] = entry.Value
	}
	return records
}

func sortChanges(changes []RevisionEntryChange) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Owner != changes[j].Owner {
			return changes[i].Owner < changes[j].Owner
		}
		return changes[i].Type < changes[j].Type
	})
}
