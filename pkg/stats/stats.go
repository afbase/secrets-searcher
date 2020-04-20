package stats

import (
    "time"
)

var (
    CommitsSearchedCount int64
    SecretsFoundCount    int64

    AppStartTime    time.Time
    AppEndTime      time.Time
    SearchStartTime time.Time
    SearchEndTime   time.Time

    CodePhaseCompleted   bool
    SearchPhaseCompleted bool
    ReportPhaseCompleted bool
)