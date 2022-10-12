package dns_utils

import (
	"reflect"
	"testing"
)

func TestGetWild(t *testing.T) {
	tests := []struct {
		qHost string
		want  []string
	}{
		{
			qHost: "example.cn",
			want: []string{
				"*.cn",
			},
		},
		{
			qHost: "a.b.c.d.example.com",
			want: []string{
				"*.com",
				"*.example.com",
				"*.d.example.com",
				"*.c.d.example.com",
				"*.b.c.d.example.com",
			},
		},
	}
	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			if got := GetWild(tt.qHost); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GetWild() = %v, want %v", got, tt.want)
			}
		})
	}
}
