package loader

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func (f *Methods) EqualExcept(other *Methods, ExceptField string) bool {
	// https://stackoverflow.com/questions/47134293/compare-structs-except-one-field-golang
	val := reflect.ValueOf(f).Elem()
	otherFields := reflect.Indirect(reflect.ValueOf(other))

	for i := 0; i < val.NumField(); i++ {
		typeField := val.Type().Field(i)
		if typeField.Name == ExceptField {
			continue
		}

		value := val.Field(i)
		otherValue := otherFields.FieldByName(typeField.Name)

		if value.Interface() != otherValue.Interface() {
			return false
		}
	}
	return true
}

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
			if got := DetectMethods(tt.rawIn); !got.EqualExcept(tt.want, "HttpClient") {
				t.Errorf("DetectMethods() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMethods_LoadRules_with_dns_error(t *testing.T) {
	m := DetectMethods("https://github.com/swoiow/blocked/raw/conf/dat/apple.txt")
	m.SetupResolver("127.0.0.153:15353")
	_, err := m.LoadRules(false)

	if !strings.Contains(err.Error(), "lookup github.com on") {
		fmt.Println(err.Error())
		t.Error("SetupResolver test failed.")
	}
}

func TestMethods_LoadRules_with_dns_success(t *testing.T) {
	m := DetectMethods("https://github.com/swoiow/blocked/raw/conf/dat/apple.txt")
	m.SetupResolver("1.0.0.1:53")
	got, err := m.LoadRules(false)
	if err != nil {
		t.Error(err)
	}
	if len(got) < 0 {
		t.Error("SetupResolver get data failed.")
	}
}

func TestMethods_LoadRules_with_rest_dns_success(t *testing.T) {
	m := DetectMethods("https://github.com/swoiow/blocked/raw/conf/dat/apple.txt")
	m.ResetResolver()
	got, err := m.LoadRules(false)
	if err != nil {
		t.Error(err)
	}
	if len(got) < 0 {
		t.Error("SetupResolver get data failed.")
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
