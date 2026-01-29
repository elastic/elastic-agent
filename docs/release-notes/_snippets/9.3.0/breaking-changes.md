## 9.3.0 [elastic-agent-9.3.0-breaking-changes]


::::{dropdown} Remove Elastic Agent global CLI flags from `otel` subcommand.
The `elastic-agent otel` subcommand no longer accepts global CLI flags that had no effect: `-c`, `--path.home`, `--path.home.unversioned`, `--path.config`, `--path.logs`, `--path.socket` and `--path.downloads`.


For more information, check [#12187](https://github.com/elastic/elastic-agent/pull/12187).

**Impact**<br>Removal of these flags can result in otel subcommand failure, if they being are used. These flags had no effect on the otel subcommand behavior.

% **Action**<br>_Add a description of the what action to take_
::::
