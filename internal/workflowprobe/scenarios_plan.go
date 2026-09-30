package workflowprobe

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"solo-0014-zone-rollout-control/internal/domain"
)

func runPlanRevisionLifecycle() error {
	harness, err := newHarness()
	if err != nil {
		return err
	}
	defer harness.close()

	var plan domain.RolloutPlan
	if err := harness.call(http.MethodPut, "/v1/plans", domain.PlanCreateInput{
		Zone:                "edge.example",
		MinimumSuccessRatio: 1,
		MaximumLatencyMS:    80,
		ExpectedNodes:       2,
	}, &plan); err != nil {
		return err
	}

	// First revision: the summary must mark the baseline and list every entry
	// as added. Entries are submitted out of order to verify stable sorting.
	var first domain.RevisionAppendResult
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/revisions", domain.RevisionCreateInput{
		Serial:    2026092501,
		Authority: "ns1.edge.example",
		Entries: []domain.ZoneEntry{
			{Owner: "www.edge.example", Type: domain.EntryCNAME, Value: "edge.example"},
			{Owner: "api.edge.example", Type: domain.EntryA, Value: "192.0.2.20"},
			{Owner: "edge.example", Type: domain.EntryA, Value: "192.0.2.10"},
		},
	}, &first); err != nil {
		return err
	}
	if err := expectStoredRevision(first.ZoneRevision, plan.ID, 2026092501); err != nil {
		return err
	}
	wantOrder := []domain.ZoneEntry{
		{Owner: "api.edge.example", Type: domain.EntryA, Value: "192.0.2.20"},
		{Owner: "edge.example", Type: domain.EntryA, Value: "192.0.2.10"},
		{Owner: "www.edge.example", Type: domain.EntryCNAME, Value: "edge.example"},
	}
	if err := expectEntries(first.Entries, wantOrder); err != nil {
		return err
	}
	if first.ContentFingerprint != domain.RevisionContentFingerprint(first.ZoneRevision) {
		return ensure(false, "first revision fingerprint does not match its content")
	}
	if len(first.ContentFingerprint) != 64 {
		return ensure(false, "content fingerprint is not a sha256 hex digest")
	}
	if first.DiffSummary.Source != domain.RevisionDiffBaseline {
		return ensure(false, "first revision diff is not baseline sourced")
	}
	if first.DiffSummary.BaseRevision != nil {
		return ensure(false, "baseline diff must not reference a predecessor")
	}
	if first.DiffSummary.RevisionID != first.ID || first.DiffSummary.Serial != first.Serial {
		return ensure(false, "baseline diff does not reference the committed revision")
	}
	if first.DiffSummary.AddedCount != 3 || first.DiffSummary.ModifiedCount != 0 || first.DiffSummary.RemovedCount != 0 {
		return ensure(false, "baseline diff counts are wrong")
	}
	if err := expectChanges(first.DiffSummary.Added, []domain.RevisionEntryChange{
		{Owner: "api.edge.example", Type: domain.EntryA, NewValue: "192.0.2.20"},
		{Owner: "edge.example", Type: domain.EntryA, NewValue: "192.0.2.10"},
		{Owner: "www.edge.example", Type: domain.EntryCNAME, NewValue: "edge.example"},
	}); err != nil {
		return err
	}

	// Second revision: the summary must be calculated against the immutable
	// predecessor that was just superseded, with added/modified/removed split
	// deterministically.
	var second domain.RevisionAppendResult
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/revisions", domain.RevisionCreateInput{
		Serial:    2026092502,
		Authority: "ns1.edge.example",
		Entries: []domain.ZoneEntry{
			{Owner: "api.edge.example", Type: domain.EntryA, Value: "192.0.2.20"},
			{Owner: "zeta.edge.example", Type: domain.EntryA, Value: "192.0.2.40"},
			{Owner: "alpha.edge.example", Type: domain.EntryA, Value: "192.0.2.5"},
			{Owner: "edge.example", Type: domain.EntryA, Value: "192.0.2.11"},
		},
	}, &second); err != nil {
		return err
	}
	if err := expectStoredRevision(second.ZoneRevision, plan.ID, 2026092502); err != nil {
		return err
	}
	if second.ContentFingerprint != domain.RevisionContentFingerprint(second.ZoneRevision) {
		return ensure(false, "second revision fingerprint does not match its content")
	}
	if second.ContentFingerprint == first.ContentFingerprint {
		return ensure(false, "different revisions share a fingerprint")
	}
	diff := second.DiffSummary
	if diff.Source != domain.RevisionDiffPrevious {
		return ensure(false, "second revision diff is not sourced from the previous revision")
	}
	if diff.RevisionID != second.ID || diff.Serial != second.Serial {
		return ensure(false, "diff does not reference the committed revision")
	}
	if diff.BaseRevision == nil {
		return ensure(false, "previous-revision diff must reference the predecessor")
	}
	if diff.BaseRevision.RevisionID != first.ID || diff.BaseRevision.Serial != first.Serial {
		return ensure(false, "diff base does not reference the previous immutable revision")
	}
	if diff.BaseRevision.ContentFingerprint != first.ContentFingerprint {
		return ensure(false, "diff base fingerprint does not match the previous revision")
	}
	if diff.AddedCount != 2 || diff.ModifiedCount != 1 || diff.RemovedCount != 1 {
		return ensure(false, "second revision diff counts are wrong")
	}
	if err := expectChanges(diff.Added, []domain.RevisionEntryChange{
		{Owner: "alpha.edge.example", Type: domain.EntryA, NewValue: "192.0.2.5"},
		{Owner: "zeta.edge.example", Type: domain.EntryA, NewValue: "192.0.2.40"},
	}); err != nil {
		return err
	}
	if err := expectChanges(diff.Modified, []domain.RevisionEntryChange{
		{Owner: "edge.example", Type: domain.EntryA, OldValue: "192.0.2.10", NewValue: "192.0.2.11"},
	}); err != nil {
		return err
	}
	if err := expectChanges(diff.Removed, []domain.RevisionEntryChange{
		{Owner: "www.edge.example", Type: domain.EntryCNAME, OldValue: "edge.example"},
	}); err != nil {
		return err
	}

	// A failed append keeps the legacy duplicate_revision error and must not
	// surface a diff summary or fingerprint.
	status, body, err := harness.roundTrip(http.MethodPatch, "/v1/plans/"+plan.ID+"/revisions", domain.RevisionCreateInput{
		Serial:    2026092501,
		Authority: "ns1.edge.example",
		Entries:   []domain.ZoneEntry{{Owner: "edge.example", Type: domain.EntryA, Value: "192.0.2.99"}},
	})
	if err != nil {
		return err
	}
	if status != http.StatusConflict {
		return ensure(false, "duplicate serial did not conflict")
	}
	if err := expectErrorBody(body, string(domain.CodeDuplicateRevision)); err != nil {
		return err
	}
	if bytes.Contains(body, []byte("diff_summary")) || bytes.Contains(body, []byte("content_fingerprint")) {
		return ensure(false, "failed append leaked a diff summary")
	}

	// Two appends moved the plan from version 1 to version 3.
	plan.Version += 2
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/activate", map[string]any{
		"expected_version": plan.Version,
	}, &plan); err != nil {
		return err
	}
	if plan.State != domain.PlanActive {
		return ensure(false, "plan was not activated")
	}

	status, body, err = harness.roundTrip(http.MethodPatch, "/v1/plans/"+plan.ID+"/revisions", domain.RevisionCreateInput{
		Serial:    2026092503,
		Authority: "ns1.edge.example",
		Entries:   []domain.ZoneEntry{{Owner: "edge.example", Type: domain.EntryA, Value: "192.0.2.12"}},
	})
	if err != nil {
		return err
	}
	if status != http.StatusConflict {
		return ensure(false, "revision append on an active plan did not conflict")
	}
	if err := expectErrorBody(body, string(domain.CodeInvalidState)); err != nil {
		return err
	}
	if bytes.Contains(body, []byte("diff_summary")) {
		return ensure(false, "rejected append after activation leaked a diff summary")
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
	if err := harness.call(http.MethodPatch, "/v1/plans/"+plan.ID+"/complete", map[string]any{
		"expected_version": completed.Version,
	}, nil); err != nil {
		return expectFailure(err, http.StatusConflict, string(domain.CodeInvalidState))
	}
	return nil
}

func expectStoredRevision(revision domain.ZoneRevision, planID string, serial uint32) error {
	switch {
	case revision.ID == "":
		return ensure(false, "append result is missing the revision id")
	case revision.PlanID != planID:
		return ensure(false, "append result lost the original plan_id field")
	case revision.Serial != serial:
		return ensure(false, "append result lost the original serial field")
	case revision.Authority != "ns1.edge.example":
		return ensure(false, "append result lost the original authority field")
	case revision.EntryCount != len(revision.Entries):
		return ensure(false, "append result lost the original entry_count field")
	case revision.CreatedAt == (time.Time{}):
		return ensure(false, "append result lost the original created_at field")
	}
	return nil
}

func expectEntries(got, want []domain.ZoneEntry) error {
	if len(got) != len(want) {
		return ensure(false, "stored entries have an unexpected length")
	}
	for index := range want {
		if got[index] != want[index] {
			return ensure(false, "stored entries are not stably sorted")
		}
	}
	return nil
}

func expectChanges(got, want []domain.RevisionEntryChange) error {
	if len(got) != len(want) {
		return ensure(false, "diff change list has an unexpected length")
	}
	for index := range want {
		if got[index] != want[index] {
			return ensure(false, "diff change list order or content is wrong")
		}
	}
	return nil
}

func expectErrorBody(body []byte, code string) error {
	var wrapped struct {
		Error domain.DomainError `json:"error"`
	}
	if err := json.Unmarshal(body, &wrapped); err != nil {
		return err
	}
	if wrapped.Error.Code != domain.ErrorCode(code) {
		return ensure(false, "failure code is not "+code)
	}
	return nil
}
