# Beats "hot reloading" for dev mode

## The problem

While debugging issues from Beats running under Elastic-Agent, often I
find myself on a cycle of:
* make a small change on a Beat (e.g. add debugging logs/messages)
* recompile the Beat
* stop the Elastic-Agent
* replace the Beat binary
* restart the Elastic-Agent
* repetat

So far this process has proven to be very cumbersome due to its many
moving parts, the fact that the Elastic-Agent is usually running on a
VM, Docker container or even Kubernets makes things even more
difficult.

## The goal
Develop an automated way for the Elastic-Agent to fetch new Beats
binaries (or packages) at every startup of the Elastic-Agent and
provide an easy (ideally automated) way to attach Delve (debugger) to
a running Beat.

## Stumbling blocks

The original goal for this
[OnWeek](https://github.com/elastic/observability-dev/issues/2116) was
quite ambitious by wanting to make the Elastic-Agent connect and take
control over a already running Beat. The original idea was to start a
Beat with Delve and then make the Elastic-Agent connect and control
it, however it proved to be very complex. The main issues found along
the way are:
1. The Elastic-Agent takes full control of the Beat process, including
   it's standard input, which is used to send some data/commands at
   startup as it can be seen here:
   https://github.com/elastic/elastic-agent/blob/ca211516c908bcd4cc01b6130f2e5e9205ecbe84/internal/pkg/core/plugin/process/start.go#L142.
2. The instructions on which command to run when starting a Beat is on
   a YAML file that is packed within the Elastic-Agent's binary,
   making changes to it troublesome.
3. Some bugs
   ([#408](https://github.com/elastic/elastic-agent/issues/408) and
   [#409](https://github.com/elastic/elastic-agent/issues/409))
   extended the investigation time.
4. For some reason the Elastic-Agent verifies twice if a Beat has
   already been downloaded, making re-download the Beats on every
   startup a dirty hack.
4. The current build and packing process for a Beat is quite slow (if
   compared to a simple `go build .`) and sometimes requires Docker.

## The current approach
Given the goals and challenges described above, the current approach
consists of:
1. Having a small HTTP server capable of mimicing the behaviour of
   `https://artifacts.elastic.co/downloads/` but instead of serving
   static files, re-compilies/packages them on every request, then
   serve the files.
2. Adding a new compilation flag (`devInsecure`) into the
   Elastic-Agent that allows Beats to be re-downloaded on every start
   up of the Elastic-Agent as well as modify other code paths as
   necessary.
3. Hardcoding a new address for the downloader (see
   [#408](https://github.com/elastic/elastic-agent/issues/408) for
   details).
4. It's assumed the HTTP server is running on the same OS/Architecture
   as the Elastic-Agent/Beats.
5. Everything can be run unsing `mage`

## How it all works
### Requirements
* Beats source code: https://github.com/elastic/beats
* Elastic-Agent source code: https://github.com/elastic/elastic-agent
* All the required tools/stup to develop Beats and Elastic-Agent
* A direct network connection between where the Elastic-Agent is
  running and where the Beats will be compiled/served.
* The Beats and Elastic-Agent are on the same version.


### Step by step
It's assumed the host and environment being debugged are the same OS
and architecture.

1. Start the HTTP server
   Go to Elastic-Agent's source code and run

   ```
   mage wip:startServer <beats_source_path> <storage_pat> <http_port>
   ```
   This will start the 'local artifacts API' on the given port

2. Open `internal/pkg/artifact/config.go`from Elastic-Agent and edit
   the default value for
   [`SourceURI`](https://github.com/elastic/elastic-agent/blob/ca211516c908bcd4cc01b6130f2e5e9205ecbe84/internal/pkg/artifact/config.go#L59)
   so it points to your local artifacts API, e.g:
   `http://192.188.42.42:8000`.
3. Recompile the Elastic-Agent in dev mode:

   ```
   mage dev:build
   ```
   This will generate a `elastic-agent` binary into the `build` folder.
4. Copy this binary to the host being debugged
5. Start the Elastic-Agent
6. Profit! The Elastic-Agent will re-download all beats from the local
   artifacts API.

### Tips
* On Linux hosts, when the Elastic-Agent is installed using the tar.gz
  package it creates a system service and puts all it's files on
  `/opt/Elastic/Agent`. For easy debugging you can run the
  Elastic-Agent directly from that folder instead of using the
  service, that way you can easily see the logs and change the log
  level. To run the Elastic-Agent with log level debug and printing
  the logs to stdout run (as root):
  
  ```
  cd /opt/Elastic/Agent
  ./elastic-agnet run -e -v -d "*"
  ```
* You can run an Elastic-Agent managed by fleet from any
* To run the Elastic-Agent with Delve and all the development build
  flags, the command is:

  ```
  dlv debug . --build-flags="-ldflags='-X github.com/elastic/elastic-agent/internal/pkg/release.devInsecure=true -X github.com/elastic/elastic-agent/internal/pkg/release.allowEmptyPgp=true -X github.com/elastic/elastic-agent/internal/pkg/release.allowUpgrade=true'" -- run -e -v -d "*"
  ```

## Next steps
* Integrate with @AndersonQ's work on [debugging the
  Elastic-Agent](https://github.com/elastic/elastic-agent/pull/403) so
  we can easily connect a debugger to a running Beat.
* Integrate with @ph's work on making the build of Elastic-Agent
  simpler and faster.
* Discussion on whether it is worht investing more time on this
  approach.
