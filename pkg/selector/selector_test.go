package selector

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		in      string
		want    map[string]string
		wantErr bool
	}{
		{"", map[string]string{}, false},
		{"a=b", map[string]string{"a": "b"}, false},
		{"a=b, ai.infra.guard/enabled=true", map[string]string{"a": "b", "ai.infra.guard/enabled": "true"}, false},
		{"a", nil, true},
		{"a=", nil, true},
		{"=b", nil, true},
		{"a b=c", nil, true},
		{"a=b c", nil, true},
	}
	for _, tt := range tests {
		got, err := Parse(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("Parse(%q) err = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if tt.wantErr {
			continue
		}
		if len(got) != len(tt.want) {
			t.Errorf("Parse(%q) = %v, want %v", tt.in, got, tt.want)
			continue
		}
		for k, v := range tt.want {
			if got[k] != v {
				t.Errorf("Parse(%q)[%s] = %q, want %q", tt.in, k, got[k], v)
			}
		}
	}
}
