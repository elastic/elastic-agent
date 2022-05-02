# Debugging the Elastic-Agent

The Elastic-Agent is a bit trickier to debug as it's basically never run it directly, most of the
time it's installed and a system service is registered to run it. Besides, it also starts several
other applications, mainly the Beats. This how-to shows how to remotely debug an elastic-agent
or beats running on another machine.

## Requirements

To remote debug we'll need:
 - [delve](https://github.com/go-delve/delve)
 - [Go](https://go.dev/dl/)

To follow along, you'll also need:
 - [Vagrant](https://www.vagrantup.com/downloads)
 - [VirtualBox](https://www.virtualbox.org/wiki/Downloads) (or other "virtualization product")

## Compile the Elastic-Agent for debug

It's necessary to compile the elastic-agent with the [`DEV=true`](https://github.com/elastic/elastic-agent/blob/main/dev-tools/mage/build.go#L54) to add the debug symbols
and disable optimisations. Setting `SNAPSHOT=true` the agent will skip signature verification of the
binaries it runs as well as will download them from the snapshop artifacts API.

Set `PLATFORMS` and `PACKAGES` to match your or the target system.
Use `EXTERNAL=true` if you do not want to compile the beats.

TODO: check if the SNAPSHOT builds are build with `DEV=true`, if not, make so.

```shell
DEV=true SNAPSHOT=true EXTERNAL=true PLATFORMS="linux/amd64" PACKAGES="tar.gz" mage -v clean package
```
