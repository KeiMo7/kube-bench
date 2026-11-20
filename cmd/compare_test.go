package cmd

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoadScanResultsAcceptsOverallAndArrayFormats(t *testing.T) {
	overall, err := loadScanResults("./testdata/result.json")
	require.NoError(t, err)
	assert.NotEmpty(t, overall)

	array, err := loadScanResults("./testdata/result_no_totals.json")
	require.NoError(t, err)
	assert.NotEmpty(t, array)
}
