//go:build windows

package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/max-zit/controlzit/internal/proto"
)

func TestQueryEvents(t *testing.T) {
	q := func(v proto.EventQuery) *proto.EventResult {
		t.Helper()
		raw, _ := json.Marshal(v)
		out, err := queryEvents(context.Background(), raw)
		if err != nil {
			t.Fatal(err)
		}
		return out.(*proto.EventResult)
	}
	r := q(proto.EventQuery{Log: "System", Hours: 720, Max: 20})
	if len(r.Events) == 0 || r.Events[0].Time.IsZero() || r.Events[0].Provider == "" {
		t.Fatalf("System log: %+v", r)
	}
	for _, e := range q(proto.EventQuery{Log: "System", Level: 2, Hours: 720, Max: 50}).Events {
		if e.Level != 1 && e.Level != 2 {
			t.Fatalf("level filter: %+v", e)
		}
	}
	for _, bad := range []string{`{"log":"Foo","hours":1,"max":1}`, `{"log":"System'; Remove-Item x; '","hours":1,"max":1}`, `{"log":"System","hours":0,"max":1}`} {
		if _, err := queryEvents(context.Background(), json.RawMessage(bad)); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	t.Logf("%d events, first %s %d %s", len(r.Events), r.Events[0].Time, r.Events[0].ID, r.Events[0].Provider)
}
