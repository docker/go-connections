module github.com/docker/go-connections

go 1.23.0

require (
	github.com/Microsoft/go-winio v0.4.21
	github.com/moby/moby/api v1.52.0-alpha.1
)

require (
	github.com/docker/go-units v0.5.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	golang.org/x/sys v0.1.0 // indirect
)

replace github.com/moby/moby/api v1.52.0-alpha.1 => github.com/austinvazquez/moby/api v1.52.0-alpha.1.0.20250814134003-5623a8fb10d4
