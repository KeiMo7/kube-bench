package cmd

import "encoding/json"

// marshalCompareJSON is split out so the diff package does not depend on the
// cmd package while tests stay easy to write.
func marshalCompareJSON(r interface{}) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}
