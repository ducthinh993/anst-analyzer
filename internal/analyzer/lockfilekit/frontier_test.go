package lockfilekit

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFrontier_ZeroValueAbsent(t *testing.T) {
	var f Frontier
	assert.False(t, f.Present(), "zero-value frontier is absent")
	assert.Equal(t, "none", f.Summary())
}

func TestFrontier_AddMarksPresent(t *testing.T) {
	var f Frontier
	f.Add("eval")
	assert.True(t, f.Present())
	assert.Equal(t, "eval", f.Summary())
}

func TestFrontier_AddDeduplicates(t *testing.T) {
	var f Frontier
	f.Add("reflection")
	f.Add("reflection")
	f.Add("eval")
	assert.Equal(t, []string{"reflection", "eval"}, f.Reasons,
		"duplicate reasons must be ignored to keep the summary stable")
	assert.Equal(t, "reflection, eval", f.Summary())
}

func TestFrontier_AddIgnoresEmpty(t *testing.T) {
	var f Frontier
	f.Add("")
	assert.False(t, f.Present(), "an empty reason must not create a frontier")
}
