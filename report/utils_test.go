package report

import "testing"

func TestReverseString1(t *testing.T) {
	tests := []struct {
		name      string
		version   string
		baseScore float32
		want      string
	}{
		{name: "Low v2", version: "v2", baseScore: 1.0, want: "Low"},
		{name: "Medium v2", version: "v2", baseScore: 4.0, want: "Medium"},
		{name: "High v2", version: "v2", baseScore: 7.0, want: "High"},
		{name: "Non Existing score v2", version: "v2", baseScore: 12.0, want: ""},
		{name: "None v3", version: "v3", baseScore: 0.0, want: "None"},
		{name: "low v3", version: "v3", baseScore: 1.0, want: "Low"},
		{name: "Medium v3", version: "v3", baseScore: 4.0, want: "Medium"},
		{name: "High v3", version: "v3", baseScore: 7.0, want: "High"},
		{name: "Critical v3", version: "v3", baseScore: 9.0, want: "Critical"},
		{name: "Non Existing score v3", version: "v3", baseScore: 12.0, want: ""},
		{name: "Non existing version", version: "v1", baseScore: 9.0, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CvssScoreToSeverity(&CVSS{Version: tt.version, BaseScore: tt.baseScore}); got != tt.want {
				t.Errorf("CvssScoreToSeverity() = %v, want %v", got, tt.want)
			}
		})
	}
}
