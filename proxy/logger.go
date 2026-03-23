package proxy

type logger interface {
	Printf(format string, args ...any)
}

type noopLogger struct{}

func (l *noopLogger) Printf(_ string, _ ...any) {
	// Do nothing :)
}
