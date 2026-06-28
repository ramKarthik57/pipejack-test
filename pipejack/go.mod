module github.com/ramKarthik57/pipejack-test/pipejack

go 1.25.0

require (
	github.com/cilium/ebpf v0.22.0
	golang.org/x/sys v0.43.0
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/cilium/ebpf => ../cilium-ebpf

replace golang.org/x/sys => ../golang-sys
