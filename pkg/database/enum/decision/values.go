package decision

//go:generate sh -c "go-genums Decision value string pkg/database/enum/decision/values.go > pkg/database/enum/decision/decision.go"/

const (
	valueNeedsInvestigation = "needs-investigation"
	valueDoNotKnowYet       = "do-not-know-yet"
	valueNotImplemented     = "not-implemented"
	valueIgnoreTestFiles    = "ignore-test-files"
	valueIgnoreExampleCode  = "ignore-example-code"
	valueIgnoreTemplateVars = "ignore-template-vars"
)
