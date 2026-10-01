package main

import "sync"

var runningAgentJob = struct {
	sync.Mutex
	id string
}{}

func activeAgentJobID() string {
	runningAgentJob.Lock()
	defer runningAgentJob.Unlock()
	return runningAgentJob.id
}
func setActiveAgentJobID(id string) {
	runningAgentJob.Lock()
	runningAgentJob.id = id
	runningAgentJob.Unlock()
}
