# PGP fallback URL in air-gapped environment workaround

## Reminders

Starting from version 8.9.0, when Elastic Agent tries to perform an upgrade, it first verifies the binary signature with the key bundled in the Agent.
This process has a backup mechanism that will use the key coming from https://artifacts.elastic.co/GPG-KEY-elastic-agent instead of the one it already has.

In an air-gapped environment, the Agent won't be able to download the remote key and therefore cannot be upgraded.

## Workaround

To resolve this issue, we need the Agent to download the remote key from a server accessible from the air-gapped environment.
As this URL is not customizable, we will have to "trick" the system by pointing https://artifacts.elastic.co/ to another host that will have the file.

## Examples

All those examples will require a server in your air-gapped environment that will expose the key you will have downloaded from https://artifacts.elastic.co/GPG-KEY-elastic-agent.

### Manual

Edit the Agent's server hosts file to add the following content:
```bash
<YOUR_HOST_IP> artifacts.elastic.co
```

Linux hosts file path:
```bash
/etc/hosts
```

Windows hosts file path:
```bash
C:\Windows\System32\drivers\etc\hosts
```

### Puppet 

```yaml
host { 'elastic-artifacts':
  ensure       => 'present'
  comment      => 'Workaround for PGP check'
  ip           => '<YOUR_HOST_IP>'
}
```

### Ansible 

```yaml
- name  : 'elastic-artifacts'
  hosts : 'all'
  become: 'yes'  

  tasks:
    - name: 'Add entry to /etc/hosts'
      lineinfile:
        path: '/etc/hosts'
        line: '<YOUR_HOST_IP> artifacts.elastic.co'
```

## TLS

Because the connection is `https`, the the certificate that the host that is impersonating `https:\\artifacts.elastic.co` will have to have `artifacts.elastic.co` as one of it's Subject Alternate Names.
