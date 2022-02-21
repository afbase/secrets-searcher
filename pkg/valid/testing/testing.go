package testing

import (
	"github.com/afbase/secrets-searcher/pkg/manip"
	va "github.com/go-ozzo/ozzo-validation/v4"
)

func findErrorForParam(r *manip.Param, errs va.Errors) (result va.Error) {
	pathNamePieces := r.PathNamePieces()

	for i, piece := range pathNamePieces {
		var errGeneric error
		var ok bool

		if errGeneric, ok = errs[piece]; !ok {
			return
		}

		// If we're not on the last element, try to get a new error map
		if i == len(pathNamePieces)-1 {
			result, _ = errGeneric.(va.Error)
			return
		}

		if errs, ok = errGeneric.(va.Errors); !ok {
			return
		}
	}
	return
}
