### Overriding DRA version for ITs

There are instances when the DRA does not generate the latest versions, which can occur during the Feature Freeze. However, the ITs need these latest versions for testing.

To address this issue, you can force the DRA version by creating the following two files:

* `.agent-version`
* `.beat-version`

The content, should be the version to be used, normally, `major.minor.patch`.

These files will be read by the `pre-command` hook, which will then create the environment variables `AGENT_VERSION`, `BEAT_VERSION`, and `AGENT_PACKAGE_VERSION`.

Those environment variables are consumed by the Mage files.