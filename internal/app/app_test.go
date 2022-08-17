//go:build unit
// +build unit

package app_test

import (
	"testing"

	"github.com/ArtemVoronov/indefinite-studies-auth-service/internal/app"
	"github.com/stretchr/testify/assert"
)

func TestDefaultHost(t *testing.T) {
	expected := ":3005"

	actual := app.GetHost()

	assert.Equal(t, expected, actual)
}
