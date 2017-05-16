teamix.openssh
==============

This role configures and (massively) hardens OpenSSH. This is done by updating hostkeys and sshd_config and ssh_config to best practices layed out by "Secure Secure Shell" (https://stribika.github.io/2015/01/04/secure-secure-shell.html).

NOTE: the ssh_config file will simply disable password based authentication for the client! So if you get "Permission denied (password, publickey)" or similar try "ssh -o PasswordAuthetication=yes"

Requirements
------------

None.

Role Variables
--------------

Uses a default config, which can be found in defaults/main.yml. Basically it just provides willshersystems.sshd with some harsh defaults and runs with it.

Dependencies
------------

  * willshersystems.sshd

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: servers
      roles:
         - { role: teamix.openssh }

License
-------

BSD

Author Information
------------------

Patrick Dreker, patrick.dreker@teamix.de
Source Code: https://bitbucket.devops.lab.teamix.net:8443/cd/teamix.openssh.git
(c) 2017 teamix GmbH
