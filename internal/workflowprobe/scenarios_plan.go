package workflowprobe

import (
	"net/http"
	"strings"

	"solo-0014-zone-rollout-control/internal/domain"
)

func runPlanRevisionLifecycle() error {
	harness, err := newHarness()
	if err != nil {
		return err
	}
	defer harness.close()

	plan, revision, err := createActivePlan(
		harness,
		"edge.example",
		2026092501,
		2,
		1,
		80,
	)
	if err != nil {
		return err
	}
	if plan.State != domain.PlanActive || revision.Serial != 2026092501 {
		return ensure(false, "plan and revision were not activated")
	}

	err = harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/revisions", domain.RevisionCreateInput{
		Serial:    2026092502,
		Authority: "ns1.edge.example",
		Entries: []domain.ZoneEntry{
			{Owner: "edge.example", Type: domain.EntryA, Value: "192.0.2.11"},
		},
	}, nil)
	if err := expectFailure(err, http.StatusConflict, string(domain.CodeInvalidState)); err != nil {
		return err
	}

	var completed domain.RolloutPlan
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/complete", map[string]any{
		"expected_version": plan.Version,
	}, &completed); err != nil {
		return err
	}
	if completed.State != domain.PlanCompleted {
		return ensure(false, "plan did not complete")
	}
	err = harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/complete", map[string]any{
		"expected_version": completed.Version,
	}, nil)
	if err := expectFailure(err, http.StatusConflict, string(domain.CodeInvalidState)); err != nil {
		return err
	}

	if err := verifyRevisionDiff(harness); err != nil {
		return err
	}
	return nil
}

// verifyRevisionDiff drives two draft appends against a fresh plan and checks
// the commit-scoped diff summary, content fingerprint, stable ordering, and
// failure compatibility directly over HTTP.
func verifyRevisionDiff(harness *harness) error {
	var plan domain.RolloutPlan
	if err := harness.call(http.MethodPut, "/v1/plans", domain.PlanCreateInput{
		Zone:                "diff.example",
		MinimumSuccessRatio: 1,
		MaximumLatencyMS:    80,
		ExpectedNodes:       2,
	}, &plan); err != nil {
		return err
	}

	// Baseline revision, entries intentionally supplied out of order.
	var baseline domain.RevisionAppendResult
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/revisions", domain.RevisionCreateInput{
		Serial:    2026093001,
		Authority: "ns1.diff.example",
		Entries: []domain.ZoneEntry{
			{Owner: "www.diff.example", Type: domain.EntryCNAME, Value: "diff.example"},
			{Owner: "api.diff.example", Type: domain.EntryA, Value: "192.0.2.20"},
			{Owner: "diff.example", Type: domain.EntryA, Value: "192.0.2.10"},
		},
	}, &baseline); err != nil {
		return err
	}
	if !isSHA256Hex(baseline.ContentFingerprint) {
		return ensure(false, "baseline revision is missing a valid content fingerprint")
	}
	if baseline.ID == "" || baseline.EntryCount != 3 || baseline.Serial != 2026093001 {
		return ensure(false, "original revision fields are not preserved in append result")
	}
	if !baseline.Diff.Baseline || baseline.Diff.PreviousRevisionID != "" || baseline.Diff.PreviousSerial != 0 {
		return ensure(false, "first revision must report baseline origin without a previous revision")
	}
	if len(baseline.Diff.Added) != 3 || len(baseline.Diff.Changed) != 0 || len(baseline.Diff.Removed) != 0 {
		return ensure(false, "baseline diff must list every entry as added")
	}
	if err := expectChangeOrder(baseline.Diff.Added, []domain.ZoneEntry{
		{Owner: "api.diff.example", Type: domain.EntryA, Value: "192.0.2.20"},
		{Owner: "diff.example", Type: domain.EntryA, Value: "192.0.2.10"},
		{Owner: "www.diff.example", Type: domain.EntryCNAME, Value: "diff.example"},
	}); err != nil {
		return err
	}

	// Second revision: one added, one changed (same owner/type, new value),
	// one removed, one untouched. Input order is shuffled again.
	var updated domain.RevisionAppendResult
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/revisions", domain.RevisionCreateInput{
		Serial:    2026093002,
		Authority: "ns1.diff.example",
		Entries: []domain.ZoneEntry{
			{Owner: "diff.example", Type: domain.EntryA, Value: "192.0.2.11"},
			{Owner: "new.diff.example", Type: domain.EntryAAAA, Value: "2001:db8::1"},
			{Owner: "api.diff.example", Type: domain.EntryA, Value: "192.0.2.20"},
		},
	}, &updated); err != nil {
		return err
	}
	if updated.Diff.Baseline {
		return ensure(false, "second revision must not be reported as baseline")
	}
	if updated.Diff.PreviousRevisionID != baseline.ID || updated.Diff.PreviousSerial != baseline.Serial {
		return ensure(false, "diff must reference the revision that was latest when the commit happened")
	}
	if !isSHA256Hex(updated.ContentFingerprint) || updated.ContentFingerprint == baseline.ContentFingerprint {
		return ensure(false, "changed content must carry a fresh content fingerprint")
	}
	if err := expectChangeOrder(updated.Diff.Added, []domain.ZoneEntry{
		{Owner: "new.diff.example", Type: domain.EntryAAAA, Value: "2001:db8::1"},
	}); err != nil {
		return err
	}
	if err := expectChangeOrder(updated.Diff.Changed, []domain.ZoneEntry{
		{Owner: "diff.example", Type: domain.EntryA, Value: "192.0.2.11"},
	}); err != nil {
		return err
	}
	changed := updated.Diff.Changed[0]
	if changed.Before != "192.0.2.10" || changed.After != "192.0.2.11" {
		return ensure(false, "changed entry must carry the previous and current values")
	}
	if err := expectChangeOrder(updated.Diff.Removed, []domain.ZoneEntry{
		{Owner: "www.diff.example", Type: domain.EntryCNAME, Value: "diff.example"},
	}); err != nil {
		return err
	}
	if updated.Diff.Removed[0].Before != "diff.example" {
		return ensure(false, "removed entry must carry the previous value")
	}

	// Same content through a different plan and a shuffled input order must
	// produce the same fingerprint, proving content-addressed determinism.
	var mirror domain.RolloutPlan
	if err := harness.call(http.MethodPut, "/v1/plans", domain.PlanCreateInput{
		Zone:                "mirror.example",
		MinimumSuccessRatio: 1,
		MaximumLatencyMS:    80,
		ExpectedNodes:       2,
	}, &mirror); err != nil {
		return err
	}
	var mirrored domain.RevisionAppendResult
	if err := harness.call(http.MethodPatch, "/v1/plans/"+mirror.ID+"/revisions", domain.RevisionCreateInput{
		Serial:    2026093001,
		Authority: "ns1.diff.example",
		Entries: []domain.ZoneEntry{
			{Owner: "diff.example", Type: domain.EntryA, Value: "192.0.2.10"},
			{Owner: "www.diff.example", Type: domain.EntryCNAME, Value: "diff.example"},
			{Owner: "api.diff.example", Type: domain.EntryA, Value: "192.0.2.20"},
		},
	}, &mirrored); err != nil {
		return err
	}
	if mirrored.ContentFingerprint != baseline.ContentFingerprint {
		return ensure(false, "fingerprint must be stable regardless of entry input order")
	}

	// Failed appends must return the legacy error codes and leave no summary
	// or state change behind.
	err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/revisions", domain.RevisionCreateInput{
		Serial:    2026093002,
		Authority: "ns1.diff.example",
		Entries:   []domain.ZoneEntry{{Owner: "diff.example", Type: domain.EntryA, Value: "192.0.2.99"}},
	}, nil)
	if err := expectFailure(err, http.StatusConflict, string(domain.CodeDuplicateRevision)); err != nil {
		return err
	}
	var current domain.RolloutPlan
	if err := harness.call(http.MethodGet, "/v1/plans/"+plan.ID, nil, &current); err != nil {
		return err
	}
	if current.LatestRevisionID != updated.ID {
		return ensure(false, "failed append must not move the latest revision")
	}
	return nil
}

func expectChangeOrder(changes []domain.RevisionEntryChange, expected []domain.ZoneEntry) error {
	if len(changes) != len(expected) {
		return ensure(false, "diff change count does not match expectation")
	}
	for index, entry := range expected {
		value := changes[index].After
		if changes[index].Kind == domain.RevisionChangeRemoved {
			value = changes[index].Before
		}
		if changes[index].Owner != entry.Owner ||
			changes[index].Type != entry.Type ||
			value != entry.Value {
			return ensure(false, "diff changes are not deterministically ordered by owner and type")
		}
	}
	return nil
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range strings.ToLower(value) {
		if r >= '0' && r <= '9' || r >= 'a' && r <= 'f' {
			continue
		}
		return false
	}
	return true
}
