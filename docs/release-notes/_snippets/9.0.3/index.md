## 9.0.3 [elastic-agent-release-notes-9.0.3]


### Features and enhancements [elastic-agent-9.0.3-features-enhancements]

* Add cumulativetodeltaprocessor to EDOT collector. [#8352](https://github.com/elastic/elastic-agent/pull/8352) [#8573](https://github.com/elastic/elastic-agent/pull/8573) [#8575](https://github.com/elastic/elastic-agent/pull/8575) [#8616](https://github.com/elastic/elastic-agent/pull/8616) [#8372](https://github.com/elastic/elastic-agent/pull/8372) 


### Fixes [elastic-agent-9.0.3-fixes]

* Address a race condition that can occur in Agent diagnostics if log rotation runs while logs are being zipped. [#8215](https://github.com/elastic/elastic-agent/pull/8215) 
* Use paths.TempDir for diagnostics actions. [#8472](https://github.com/elastic/elastic-agent/pull/8472) 
* Relax file ownership check to allow admin re-enrollment on Windows. [#8503](https://github.com/elastic/elastic-agent/pull/8503) [#7794](https://github.com/elastic/elastic-agent/issues/7794)

  On Windows, the agent previously enforced a strict file ownership (SID) check during re-enrollment, which prevented legitimate admin users from re-enrolling the agent if the owner did not match. This PR changes the Windows-specific logic to a no-op, allowing any admin to re-enroll the agent. This restores usability for admin users, but reintroduces the risk that privileged re-enrollment can break unprivileged installs. The Unix-specific ownership check remains unchanged.
  

