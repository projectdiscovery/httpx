package runner

type ResumeCfg struct {
	ResumeFrom   string
	Index        int
	current      string
	currentIndex int
	// lastCompletedIndex tracks the index of the last item that was fully processed
	// This ensures we don't skip items that were in-progress when interrupted
	lastCompletedIndex int
	lastCompletedItem  string
}
