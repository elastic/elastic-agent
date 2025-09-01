package agentservice

var (
	StopChanBeat chan bool
)

func init() {
	StopChanBeat = make(chan bool)
}
