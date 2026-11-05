package ai

import "strings"

// AdmissionQueueFull reports the AI HUB 429 that means this model's admission
// queue is full. Other rate limits and timeouts are not this error.
func AdmissionQueueFull(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "admission_queue_full") ||
		strings.Contains(lower, "admission queue is at capacity")
}
