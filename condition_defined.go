package ladon

// DefinedCondition is a condition which is fulfilled if a field is defined
type DefinedCondition struct{}

// Fulfills returns true if the given value is a string and is defined
func (c *DefinedCondition) Fulfills(value interface{}, _ *Request) bool {
	return value != nil
}

// GetName returns the condition's name.
func (c *DefinedCondition) GetName() string {
	return "DefinedCondition"
}
