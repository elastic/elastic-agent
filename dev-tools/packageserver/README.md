# Beats hot reloading for dev mode

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



