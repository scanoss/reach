module github.com/scanoss/reach

go 1.26.0

require (
	github.com/dlclark/regexp2 v1.11.5
	github.com/go-enry/go-enry/v2 v2.9.2
	github.com/package-url/packageurl-go v0.1.6
	github.com/pelletier/go-toml/v2 v2.4.3
	github.com/rs/zerolog v1.34.0
	github.com/sabhiram/go-gitignore v0.0.0-20210923224102-525f6e181f06
	github.com/smacker/go-tree-sitter v0.0.0-20240827094217-dd81d9e9be82
	go.yaml.in/yaml/v3 v3.0.6
)

require (
	github.com/go-enry/go-oniguruma v1.2.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	golang.org/x/sys v0.12.0 // indirect
)

// v0.1.2 was tagged out of order: it contains v0.2.0. Use v0.3.0 or later.
retract v0.1.2
