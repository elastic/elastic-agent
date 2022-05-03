# Debugging the Elastic-Agent

The Elastic-Agent is a bit trickier to debug as it's basically never run it directly, most of the
time it's installed and a system service is registered to run it. Besides, it also starts several
other applications, mainly the Beats. This how-to shows how to remotely debug an elastic-agent
or beats running on another machine.

## In a hurry? Go to [tl;dr](#tl;dr)

## Requirements

To remote debug we'll need:
- [Delve](https://github.com/go-delve/delve)
- Any Delve [frontend client](https://github.com/go-delve/delve/blob/master/Documentation/EditorIntegration.md).
Delve already comes with a terminal client and your IDE is likely one as well.

To follow along, you'll also need:
 - [Vagrant](https://www.vagrantup.com/downloads)
 - [VirtualBox](https://www.virtualbox.org/wiki/Downloads) (or other "virtualization product")

## What we'll do

 - compile the elastic-agent (and optionally the beats) to allow debugging
 - start a Vagrant VM. Delve is already installed there ;)
 - install the elastic-agent on this VM
 - spin up a Delve backend server connected to the running elastic-agent on the VM
 - use Delve's terminal client to connect to the Delve server on the VM
 - set up a breakpoint
 - make the elastic-agent to hit the breakpoint

## Compile the Elastic-Agent for debug

It's necessary to compile the elastic-agent with the [`DEV=true`](https://github.com/elastic/elastic-agent/blob/main/dev-tools/mage/build.go#L54)
to add the debug symbols and disable optimisations. Setting `SNAPSHOT=true` so the
agent will skip signature verification of the
binaries it runs as well as will download them from the snapshop artifacts API.

Set `PLATFORMS` and `PACKAGES` environment variables to match yours or the target system.
Use `EXTERNAL=true` if you do not want to compile the beats, downloading them instead.

TODO: check if the SNAPSHOT builds are build with `DEV=true`, if not, make so.

On the elastic-agent's repo root run:
```shell
DEV=true SNAPSHOT=true EXTERNAL=true PLATFORMS="linux/amd64" PACKAGES="tar.gz" mage -v clean package
```
the elastic-agent artifact will be placed on `build/distributions`.

## Spin up a VM using Vagrant

There is a [Vagrantfile](https://github.com/elastic/elastic-agent/blob/main/Vagrantfile)
on the repository root. A `dev` VM is defined there, it forwards the port `4242` to
the hosts `4242` port and mounts the repository's root to `/vagrant`.

To spin up and connect to the VM:

```shell
vagrant up dev
vagrant ssh dev
```

It can be destroyed with:
```shell
vagrant destroy dev
```

## Delve, the debugger

There are several options to [invoke Delve](https://github.com/go-delve/delve/blob/master/Documentation/usage/dlv.md)
to debug a program. In short
```shell
dlv <delve flags> <delve command> <target to debug> -- <args to the target>
# Eg:
dlv --headless=true exec ./elastic-agnet -- diagnostics collect
```

### Remote debug

In order to remote debug an application we need 3 things:
 - the process we want to debug
 - a Delve instance running as a server:
   - it'll attach or run the process we want to debug
 - a frontend client, which will connect to the Delve server.
   - Usually your IDE can connect directly to the Delve server

### Delve backend server

In order to run Delve as a backend server the `--headless` cli flag is ised.
It can be used with any command (`debug`, `test`, `exec`, `attach`, `core` or `replay`).
Therefore we can either attach to a running process (`dlv attach`) or start it
through Delve (`dlv exec|debug`).

As the elastic-agent and beats are already running, we'll attach to them with:
```shell
dlv --listen=:4242 --headless=true --api-version=2 --accept-multiclient attach PID
```
where:
 - `--listen=:4242`: server address, here we're just passing in the port `4242`
 - `--headless=true`: run only the server, in headless mode
 - `--api-version=2`: defines the JSON-RPC API version
 - `--accept-multiclient`: allows multiple client connections

### Client connecting to the Delve server

There are several options for [frontend clients](https://github.com/go-delve/delve/blob/master/Documentation/EditorIntegration.md). [Goland](https://www.jetbrains.com/help/go/attach-to-running-go-processes-with-debugger.html#step-3-create-the-remote-run-debug-configuration-on-the-client-computer),
[VS Code](https://github.com/golang/vscode-go/blob/master/docs/debugging.md#launchjson-attributes) and [Emacs](https://emacs-lsp.github.io/dap-mode/page/configuration/#go) all have plugins for Delve.

#### `dlv connect`

For the sake of keeping this guide generic, let's use Delve terminal client.
If you followed along up to here, you should have a vagrant VirtualBox VM:
- forwarding its port 4242 to you your localhost:4242
- the elastic-agent running
- a delve server attached to the running elastic agent listening on port 4242

Now you can connect to the remote Delve server using Delve's terminal client. Let's
do it, set a breakpoint and see it all working. We'll set a breakpoint on the
elastic-agent's `status` command, so we can easily hit this breakpoint whenever
we want. By the time this guide was written the code for the status command was
located on [internal/pkg/agent/control/server/server.go:152](https://github.com/elastic/elastic-agent/blob/main/internal/pkg/agent/control/server/server.go#L152).

- On the host (a.k.a your machine)
```shell
dlv connect localhost:4242
# it'll open Delve's console
b internal/pkg/agent/control/server/server.go:152 # sets the breakpoint
c # continues the execution until the code hits any breakpoint
```

- On the VM
```shell
sudo /opt/Elastic/Agent/elastic-agent status
```

### Elastic Stack

In order to enroll an elastic-agent with Fleet a Elastic Stack is needed. The
easiest way is to spin up one in [Cloud](https://cloud.elastic.co). Anyway
[`elastic-package`](https://github.com/elastic/elastic-package/releases) works too.
The elastic-package uses docker and docker compose to spin up the stack.

Download and run `elastic-package` on your machine:

```shell
curl -s https://api.github.com/repos/elastic/elastic-package/releases/latest \
| grep "browser_download_url.*linux_amd64.tar.gz" \
| cut -d : -f 2,3 \
| tr -d \" \
| wget -i -
tar -xf elastic-package*.tar.gz

eval "$(elastic-package stack shellinit)"
./elastic-package ... TODO: continue here
```

## tl;dr

### On your machine
```shell
cd /path/to/your/elastic-agent/repo
# Omit EXTERNAL=true to compile the beats as well
DEV=true SNAPSHOT=true EXTERNAL=true PLATFORMS="linux/amd64" PACKAGES="tar.gz" mage -v clean package
vagrant up dev
vagrant ssh dev
```

### On the Vagrant machine

```shell
sudo -i
rm -rf elastic-agent* && \
cp /vagrant/build/distributions/elastic-agent-*.tar.gz ./ && \
mkdir -p elastic-agent && \
tar --strip-components=1 -xf elastic-agent-*.tar.gz -C elastic-agent && \
cd elastic-agent
# Install and enroll the elastic agent (or run stand alone)
# --non-interactive: will not prompt for confirmation
# --force: will replace a previously installed elastic-agent if any is present
sudo ./elastic-agent install --non-interactive --force --url=SOME_URL --enrollment-token=SOME_TOKEN
```

 - find the process PID to connect to
```shell
ps aux | grep elastic-agent # or filebeat, metricbeat, ...
```
```shell
root@ubuntu-impish:~# ps aux | grep elastic-agent
root       24953  0.7  3.0 1799448 62296 ?       Ssl  08:29   0:05 /opt/Elastic/Agent/elastic-agent
root        8891  0.0  0.0      0     0 ?        Zs   12:59   0:00 [elastic-agent] <defunct>
root        8916  0.0  0.0      0     0 ?        Zs   12:59   0:00 [elastic-agent] <defunct>
```

Ignore any `[elastic-agent] <defunct>`, we want the `/opt/Elastic/Agent/elastic-agent`,
here it's PID 24953.
Now that we now the PID, we can attach Delve to it:

```shell
dlv --listen=:4242 --headless=true --api-version=2 --accept-multiclient attach 24953
```

### Back to your machine

```shell
dlv connect localhost:4242
# it'll open Delve's console
b internal/pkg/agent/control/server/server.go:152 # sets the breakpoint
c # continues the execution until the code hits any breakpoint
```

 - on another terminal:
```shell
vagrant ssh dev
```

### On the new session on the VM

```shell
sudo /opt/Elastic/Agent/elastic-agent status
```
