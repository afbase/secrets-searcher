package diff

import (
	"fmt"
	"strings"
)

type (
	Line struct {
		fmt.Stringer
		line       string
		pre        string
		Code       string
		IsAdd      bool
		IsDel      bool
		IsAddOrDel bool
	}
)

func NewLine(lineString string) *Line {
	if lineString == "" {
		return &Line{}
	}

	pre := lineString[:1]
	isAdd := pre == "+"
	isDel := pre == "-"

	return &Line{
		line:       lineString,
		pre:        pre,
		Code:       lineString[1:],
		IsAdd:      isAdd,
		IsDel:      isDel,
		IsAddOrDel: isAdd || isDel,
	}
}

func (l *Line) String() string {
	return l.line
}

func (l *Line) CodeContains(substr string) bool {
	return strings.Contains(l.Code, substr)
}

func (l *Line) CodeStartsWith(substr string) bool {
	return strings.HasPrefix(l.Code, substr)
}

func (l *Line) CodeEndsWith(substr string) bool {
	return strings.HasSuffix(l.Code, substr)
}
