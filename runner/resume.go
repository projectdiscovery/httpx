package runner

type ResumeCfg struct {
	ResumeFrom string
	Index      int
	// current        string
	// currentIndex   int
	completedIndex int    // number of results actually printed
	lastPrinted    string // last host printed
}
