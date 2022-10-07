package dns_utils

import "strings"

func GetWild(h string) []string {
	var bucket []string
	firstFlag := true
	splitHost := strings.Split(h, ".")
	newHost := ""
	for i := len(splitHost) - 1; i > 0; i-- {
		if firstFlag {
			newHost = splitHost[i]
			firstFlag = false
		} else {
			newHost = splitHost[i] + "." + newHost
		}
		bucket = append(bucket, "*."+newHost)
	}
	return bucket
}

func IsHostname(s string) bool {
	return !strings.Contains(s, ".")
}

func PureDomain(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}
