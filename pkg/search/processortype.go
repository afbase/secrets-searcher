package search

//go:generate stringer -type ProcessorType

type ProcessorType int

const (
	Regex ProcessorType = iota
	PEM
	Setter
	Entropy
	FileSignature
)

func ProcessorTypes() []ProcessorType {
	return []ProcessorType{
		Regex,
		PEM,
		Setter,
		Entropy,
		FileSignature,
	}
}

func NewProcessorTypeFromValue(val string) ProcessorType {
	for _, e := range ProcessorTypes() {
		if e.String() == val {
			return e
		}
	}
	panic("unknown processor type: " + val)
}

func ValidProcessorTypeValues() (result []string) {
	processorTypes := ProcessorTypes()
	result = make([]string, len(processorTypes))
	for i := range processorTypes {
		result[i] = processorTypes[i].String()
	}
	return
}
