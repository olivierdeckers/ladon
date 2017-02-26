package ladon

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConditionsAppend(t *testing.T) {
	cs := Conditions{}
	c := &CIDRCondition{}
	cs.AddCondition("clientIP", c)
	assert.Equal(t, c, cs["clientIP"])
}

func TestMarshalUnmarshalNative(t *testing.T) {
	css := &Conditions{
		"clientIP": &CIDRCondition{CIDR: "127.0.0.1/0"},
		"owner":    &EqualsSubjectCondition{},
	}
	out, err := json.Marshal(css)
	require.Nil(t, err)
	t.Logf("%s", out)

	cs := Conditions{}
	require.Nil(t, cs.UnmarshalJSON(out))
}

func TestMarshalUnmarshal(t *testing.T) {
	css := &Conditions{
		"clientIP": &CIDRCondition{CIDR: "127.0.0.1/0"},
		"owner":    &EqualsSubjectCondition{},
	}
	out, err := json.Marshal(css)
	require.Nil(t, err)
	t.Logf("%s", out)

	cs := Conditions{}
	require.Nil(t, json.Unmarshal([]byte(`{
	"owner": {
		"type": "EqualsSubjectCondition"
	},
	"clientIP": {
		"type": "CIDRCondition",
		"options": {
			"cidr": "127.0.0.1/0"
		}
	},
	"user": {
		"type": "DefinedCondition"
	},
	"role": {
		"type": "StringEqualCondition",
		"options": {
			"equals": "admin"
		}
	}
}`), &cs))

	require.Len(t, cs, 4)
	assert.IsType(t, &EqualsSubjectCondition{}, cs["owner"])
	assert.IsType(t, &CIDRCondition{}, cs["clientIP"])
	assert.IsType(t, &DefinedCondition{}, cs["user"])
	assert.IsType(t, &StringEqualCondition{}, cs["role"])

}
