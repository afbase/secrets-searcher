package interact

import (
	"github.com/afbasse/secrets-searcher/pkg/interact/progress"
	"github.com/afbasse/secrets-searcher/pkg/logg"
)

type Interact struct {
	Enabled bool
	log     logg.Logg
}

func New(enabled bool, log logg.Logg) *Interact {
	return &Interact{
		Enabled: enabled,
		log:     log,
	}
}

func (i *Interact) NewProgress() *progress.Progress {
	if !i.Enabled {
		return nil
	}
	return progress.New(i.log.Output().(*logg.StdoutFileWriter), i.log)
}

func (i *Interact) SpinWhile(message string, doFunc func()) {
	if !i.Enabled {
		doFunc()
		return
	}

	prog := progress.New(i.log.Output().(*logg.StdoutFileWriter), i.log)
	spinner := prog.AddSpinner(message)

	doFunc()

	spinner.Incr()
	prog.Wait()
}
