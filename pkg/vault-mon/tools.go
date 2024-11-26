package vaultmon

func getEmptyStringIfEmpty(data []string) string {
	if len(data) > 0 {
		return data[0]
	}
	return ""
}
