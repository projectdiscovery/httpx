package runner

type ResumeCfg struct {
	ResumeFrom   string
	Index        int
	current      string
	currentIndex int
	// completedIndex int
	lastPrinted string
}
