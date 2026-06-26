package engine

// FailMode controls firewall behavior when OPA is unavailable.
type FailMode int

const (
	// FailOpen allows all traffic silently when OPA is unavailable.
	FailOpen FailMode = iota
	// FailClosed blocks all traffic when OPA is unavailable (default).
	FailClosed
	// FailLog allows traffic but logs would-be blocks when OPA is unavailable.
	FailLog
)

// String returns the string representation of the fail mode.
func (m FailMode) String() string {
	switch m {
	case FailOpen:
		return "open"
	case FailClosed:
		return "closed"
	case FailLog:
		return "log"
	default:
		return "unknown"
	}
}

// ParseFailMode parses a fail-mode string into a FailMode value.
func ParseFailMode(s string) FailMode {
	switch s {
	case "open":
		return FailOpen
	case "closed":
		return FailClosed
	case "log":
		return FailLog
	default:
		return FailClosed
	}
}
