package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// RevisionContentFingerprint returns a stable SHA-256 fingerprint of the
// immutable revision content. Only serial, authority and normalized entries
// participate, so identical content always produces the same digest regardless
// of generated ids or timestamps.
func RevisionContentFingerprint(revision ZoneRevision) string {
	entries := append([]ZoneEntry(nil), revision.Entries...)
	SortZoneEntries(entries)
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

// SortZoneEntries orders entries by owner, then type, then value. Revisions
// already store normalized, sorted entries; sorting again keeps long entry
// lists stable even when callers construct revisions directly.
func SortZoneEntries(entries []ZoneEntry) {
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Owner != entries[j].Owner {
			return entries[i].Owner < entries[j].Owner
		}
		if entries[i].Type != entries[j].Type {
			return entries[i].Type < entries[j].Type
		}
		return entries[i].Value < entries[j].Value
	})
}

// BuildRevisionDiffSummary produces a deterministic diff between a revision and
// its predecessor. A zero-valued predecessor marks the plan's first revision,
// whose entries are reported as added against the baseline.
func BuildRevisionDiffSummary(revision ZoneRevision, predecessor *ZoneRevision) RevisionDiffSummary {
	currentEntries := append([]ZoneEntry(nil), revision.Entries...)
	SortZoneEntries(currentEntries)

	summary := RevisionDiffSummary{
		RevisionID: revision.ID,
		Serial:     revision.Serial,
		Added:      []RevisionEntryChange{},
		Modified:   []RevisionEntryChange{},
		Removed:    []RevisionEntryChange{},
	}

	if predecessor == nil {
		summary.Source = RevisionDiffBaseline
		for _, entry := range currentEntries {
			summary.Added = append(summary.Added, RevisionEntryChange{
				Owner:    entry.Owner,
				Type:     entry.Type,
				NewValue: entry.Value,
			})
		}
		summary.AddedCount = len(summary.Added)
		return summary
	}

	summary.Source = RevisionDiffPrevious
	summary.BaseRevision = &RevisionDiffBase{
		RevisionID:         predecessor.ID,
		Serial:             predecessor.Serial,
		ContentFingerprint: RevisionContentFingerprint(*predecessor),
	}

	previousEntries := append([]ZoneEntry(nil), predecessor.Entries...)
	SortZoneEntries(previousEntries)
	summary.Added, summary.Modified, summary.Removed = diffZoneEntries(previousEntries, currentEntries)
	summary.AddedCount = len(summary.Added)
	summary.ModifiedCount = len(summary.Modified)
	summary.RemovedCount = len(summary.Removed)
	return summary
}

// diffZoneEntries compares two sorted, duplicate-free entry lists. Entries are
// identified by owner and type; values that stay equal are unchanged, remaining
// values pair up as modifications, and unmatched entries are added or removed.
// For keys allowing multiple values, unmatched values on each side are paired
// deterministically in sorted order before the leftovers are reported.
func diffZoneEntries(previous, current []ZoneEntry) (added, modified, removed []RevisionEntryChange) {
	added = []RevisionEntryChange{}
	modified = []RevisionEntryChange{}
	removed = []RevisionEntryChange{}

	previousByKey := groupZoneEntries(previous)
	currentByKey := groupZoneEntries(current)

	keys := make([]zoneEntryKey, 0, len(previousByKey)+len(currentByKey))
	seen := make(map[zoneEntryKey]struct{}, len(previousByKey)+len(currentByKey))
	for key := range previousByKey {
		if _, ok := seen[key]; ok == false {
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
	}
	for key := range currentByKey {
		if _, ok := seen[key]; ok == false {
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Owner != keys[j].Owner {
			return keys[i].Owner < keys[j].Owner
		}
		return keys[i].Type < keys[j].Type
	})

	for _, key := range keys {
		oldValues := previousByKey[key]
		newValues := currentByKey[key]
		common := map[string]int{}
		for _, value := range oldValues {
			common[value]++
		}
		unmatchedOld := make([]string, 0)
		unmatchedNew := make([]string, 0)
		for _, value := range newValues {
			if common[value] > 0 {
				common[value]--
				continue
			}
			unmatchedNew = append(unmatchedNew, value)
		}
		for value, count := range common {
			for index := 0; index < count; index++ {
				unmatchedOld = append(unmatchedOld, value)
			}
		}
		sort.Strings(unmatchedOld)
		sort.Strings(unmatchedNew)

		pairs := len(unmatchedOld)
		if len(unmatchedNew) < pairs {
			pairs = len(unmatchedNew)
		}
		for index := 0; index < pairs; index++ {
			modified = append(modified, RevisionEntryChange{
				Owner:    key.Owner,
				Type:     key.Type,
				OldValue: unmatchedOld[index],
				NewValue: unmatchedNew[index],
			})
		}
		for index := pairs; index < len(unmatchedNew); index++ {
			added = append(added, RevisionEntryChange{
				Owner:    key.Owner,
				Type:     key.Type,
				NewValue: unmatchedNew[index],
			})
		}
		for index := pairs; index < len(unmatchedOld); index++ {
			removed = append(removed, RevisionEntryChange{
				Owner:    key.Owner,
				Type:     key.Type,
				OldValue: unmatchedOld[index],
			})
		}
	}

	sortEntryChanges(added)
	sortEntryChanges(modified)
	sortEntryChanges(removed)
	return added, modified, removed
}

type zoneEntryKey struct {
	Owner string
	Type  EntryType
}

func groupZoneEntries(entries []ZoneEntry) map[zoneEntryKey][]string {
	grouped := make(map[zoneEntryKey][]string)
	for _, entry := range entries {
		key := zoneEntryKey{Owner: entry.Owner, Type: entry.Type}
		grouped[key] = append(grouped[key], entry.Value)
	}
	for key := range grouped {
		sort.Strings(grouped[key])
	}
	return grouped
}

func sortEntryChanges(changes []RevisionEntryChange) {
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Owner != changes[j].Owner {
			return changes[i].Owner < changes[j].Owner
		}
		if changes[i].Type != changes[j].Type {
			return changes[i].Type < changes[j].Type
		}
		if changes[i].OldValue != changes[j].OldValue {
			return changes[i].OldValue < changes[j].OldValue
		}
		return changes[i].NewValue < changes[j].NewValue
	})
}
