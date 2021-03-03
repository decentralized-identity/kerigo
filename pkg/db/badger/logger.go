package badger

type NoOpLogger struct {
}

func (r *NoOpLogger) Errorf(s string, i ...interface{}) {
}

func (r *NoOpLogger) Warningf(s string, i ...interface{}) {
}

func (r *NoOpLogger) Infof(s string, i ...interface{}) {
}

func (r *NoOpLogger) Debugf(s string, i ...interface{}) {
}
