package filesig

import (
	"path"
	"regexp"
	"strings"

	"github.com/afbase/secrets-searcher/pkg/logg"
	"github.com/afbase/secrets-searcher/pkg/manip"
	"github.com/afbase/secrets-searcher/pkg/search/contract"
)

type Processor struct {
	name        string
	part        string // "extension", "filename", or "path"
	match       string // exact match value
	re          *regexp.Regexp
	description string
	log         logg.Logg
}

func NewProcessor(name, part, match, regexString, description string, log logg.Logg) *Processor {
	var re *regexp.Regexp
	if regexString != "" {
		re = regexp.MustCompile(regexString)
	}

	return &Processor{
		name:        name,
		part:        part,
		match:       match,
		re:          re,
		description: description,
		log:         log,
	}
}

func (p *Processor) GetName() string {
	return p.name
}

func (p *Processor) FindResultsInFileChange(job contract.ProcessorJobI) (err error) {
	filePath := job.FileChange().Path

	if !p.matches(filePath) {
		return
	}

	fileBasename := path.Base(filePath)
	desc := p.description
	if desc == "" {
		desc = p.name
	}

	job.SubmitResult(&contract.Result{
		FileRange:    manip.NewFileRange(1, 0, 1, len(filePath)),
		SecretValue:  filePath,
		FileBasename: fileBasename,
		FindingExtras: []*contract.ResultExtra{
			{
				Key:    "file-signature",
				Header: "File signature match",
				Value:  desc,
			},
		},
	})

	return
}

func (p *Processor) matches(filePath string) bool {
	switch p.part {
	case "extension":
		ext := path.Ext(filePath)
		if ext != "" {
			ext = ext[1:] // remove leading dot
		}
		return strings.EqualFold(ext, p.match)
	case "filename":
		basename := path.Base(filePath)
		return strings.EqualFold(basename, p.match)
	case "path":
		if p.re != nil {
			return p.re.MatchString(filePath)
		}
		return strings.Contains(filePath, p.match)
	}
	return false
}
