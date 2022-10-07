package loader

import (
	"reflect"
	"testing"
)

func TestDetectMethods(t *testing.T) {
	tests := []struct {
		name  string
		rawIn string
		want  *Methods
	}{
		{"test_normal_file", "/a/b/c.txt", &Methods{
			RawInput: "/a/b/c.txt", OutInput: "/a/b/c.txt", IsRules: true,
		}},
		{"test_normal_cache", "/A/b/c.dat", &Methods{
			RawInput: "/A/b/c.dat", OutInput: "/A/b/c.dat", IsCache: true,
		}},

		{"test_http", "http://aa.com/a.txt", &Methods{
			RawInput: "http://aa.com/a.txt", OutInput: "http://aa.com/a.txt", IsRules: true, IsHttp: true, IsRemote: true,
		}},
		{"test_https", "https://aa.com/b.txt", &Methods{
			RawInput: "https://aa.com/b.txt", OutInput: "https://aa.com/b.txt", IsRules: true, IsHttps: true, IsRemote: true,
		}},

		{"test_cache", "cache+/AAA/bbb/ccc.dat", &Methods{
			RawInput: "cache+/AAA/bbb/ccc.dat", OutInput: "/AAA/bbb/ccc.dat", IsCache: true,
		}},
		{"test_cache+http", "cache+http://a.com/b.txt", &Methods{
			RawInput: "cache+http://a.com/b.txt", OutInput: "http://a.com/b.txt", IsCache: true, IsHttp: true, IsRemote: true,
		}},
		{"test_cache+https", "cache+https://b.com/c.txt", &Methods{
			RawInput: "cache+https://b.com/c.txt", OutInput: "https://b.com/c.txt", IsCache: true, IsHttps: true, IsRemote: true,
		}},

		{"test_hostsParser", "hosts+https://x.com/y.txt", &Methods{
			RawInput: "hosts+https://x.com/y.txt", OutInput: "https://x.com/y.txt", UseHostsParser: true, IsRules: true, IsHttps: true, IsRemote: true,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectMethods(tt.rawIn); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DetectMethods() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMethods_LoadRules(t *testing.T) {
	m := DetectMethods("https://github.com/swoiow/blocked/raw/conf/dat/apple.txt")
	got, err := m.LoadRules(false)
	if err != nil {
		t.Error(err)
	}

	if !Contains(got, "*.icloud.com") {
		t.Error("LoadRules with wildcard data failed.")
	}

	if Contains(got, "*.apple.com") {
		t.Error("LoadRules with unknown data.")
	}
}

func Contains[T comparable](s []T, e T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}
