# proactcloud.openssh

This role configures and (massively) hardens OpenSSH. This is done by updating hostkeys and sshd_config and ssh_config to best practices layed out by "Secure Secure Shell" (<https://stribika.github.io/2015/01/04/secure-secure-shell.html>).

**NOTE:** the ssh_config file will simply disable password based authentication for the client! So if you get `Permission denied (password, publickey)` or similar try `ssh -o PasswordAuthentication=yes`

## Limitations / Caveat

To manipulate OpenSSH hostkeys we need the python cryptography module installed. Unfortunately on Ubuntu 14.04/16.04 the packaged version is too old (1.2.3) or simply unavailable, and so is not able to output OpenSSH compatible keys. This role will install the most up-to-date version from pip. This *may* adversely affect other software relying on python cryptography, so in that case you may want to correct this afterwards, by remove the pip version (`pip uninstall cryptography`) and reinstalling the packaged version (`apt-get install --reinstall  python-cryptography`).

As CentOS (and probably other RedHat based distributions) unconditionally regenerate all possible host keys we will not remove the ECDSA host key, but rather enforce it to 521 bits.

## Role Variables

Uses a default config, which can be found in `defaults/main.yml`. Basically it just provides `willshersystems.sshd` with some harsh defaults and runs with it.

* `pacopenssh_allow_group`: define a group, which will be allowed to login using ssh. This group will be created, when it doesn't exist. Default: ssh_allow
* `pacopenssh_sshd`: complex hash using the same template as willshersystems.sshd (see there).

 The default configuration is:

 ```yaml
 pacopenssh_sshd:
  KexAlgorithms: curve25519-sha256@libssh.org, diffie-hellman-group-exchange-sha256
  Protocol: 2
  HostKey:
    - "{{ pacopenssh_conf_dir }}/ssh_host_rsa_key"
    - "{{ pacopenssh_conf_dir }}/ssh_host_ed25519_key"
  PasswordAuthentication: "no"
  PermitRootLogin: without-password
  ChallengeResponseAuthentication: "no"
  PubkeyAuthentication: "yes"
  AllowGroups: "{{ ssh_allow_group }}"
  Ciphers: chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
  MACs: hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com
```

Please be aware that this config may lockout older clients and will **NOT ALLOW** password-based authentication for anyone. **Ensure that SSH Key based Logins are configured and working before deploying on a server!**

## Dependencies

* Ansible Module openssh_hostkey (<https://github.com/proact-de/ansible-module-opensshhostkeys>)
* willshersystems.sshd (<https://github.com/willshersystems/ansible-sshd>)

## Example Playbook

```yml
- hosts: servers
  roles:
     - { role: proactcloud.openssh, ssh_allow_group: mysshgrp }
```

## License

Copyright 2019 Proact Deutschland GmbH

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

<http://www.apache.org/licenses/LICENSE-2.0>

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## Author Information

Patrick Dreker <patrick.dreker@proact.de>

[![Build Status (master)](https://travis-ci.org/proact-de/ansible-role-openssh.svg?branch=master)](https://travis-ci.org/proact-de/ansible-role-openssh)
