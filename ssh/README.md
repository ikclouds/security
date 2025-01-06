# Secure shell (SSH)

- [Secure shell (SSH)](#secure-shell-ssh)
  - [SSH Protocol](#ssh-protocol)
  - [Openssh-client](#openssh-client)
    - [Install openssh-client](#install-openssh-client)
    - [Generate SSH keys](#generate-ssh-keys)
    - [SSH utils](#ssh-utils)
      - [ssh](#ssh)
      - [ssh-copy-id](#ssh-copy-id)
      - [ssh-agent](#ssh-agent)
      - [ssh-add](#ssh-add)
  - [openssh-server](#openssh-server)
  - [ufw firewall](#ufw-firewall)
  - [Information sources](#information-sources)

## SSH Protocol

SSH runs on top of the TCP/IP protocol suite. SSH incorporates encryption and authentication via public key cryptography. Public key cryptography is a way to encrypt or sign data, using public and private keys. Port 22 is the default port for SSH.

Used for:

- connecting remotely to the host or service in the cloud or local network
- securely transferring files
- remotely managing servers
- bypassing firewall

## Openssh-client

### Install openssh-client

```bash

# Search in global repository
apt search ssh | grep ssh
apt search ssh | grep openssh

# List of what is installed
apt list --installed | grep ssh
apt list --installed | grep openssh
sudo apt install openssh-client
dpkg -l | grep ssh
dpkg -l openssh-client

# List files
dpkg -L openssh-client
dpkg -L openssh-client | grep bin

# Finding what is installed
dpkg -s openssh-client
dpkg -S openssh-client  # doc
```

### Generate SSH keys

```bash
# OPTIONS:
# -C comment Provides a new comment
# -b bits default is 3072 bits
# -t dsa | ecdsa | ecdsa-sk | ed25519 | ed25519-sk | rsa
# -f filename Specifies the filename of the key file
# -l Show fingerprint of specified public key file.
# -p Requests changing the passphrase
# -N Provides the new passphrase
# -m key_format Specify a key format for key generation, the -i (import), -e (export) conversion options: PEM

ssh-keygen -C username@email.com
ssh-keygen -l -f ~/.ssh/id_rsa  # SHA Secure Hash Algorithm

ls -l ~/.ssh/
cat ~/.ssh/id_rsa.pub
```

### SSH utils

#### ssh

```bash
# Connect using SSH with username
w
ip -br a
ssh username@127.0.0.1
cat ~/.ssh/known_hosts
w
```

#### ssh-copy-id

```bash
# Copy public SSH key
ssh-copy-id username@127.0.0.1
cat ~/.ssh/authorized_keys

# Connect using SSH with public SSH key
ssh -i ~/id_rsa 127.0.0.1
w
```

#### ssh-agent

```bash
# OPTIONS:
# -k Kill the current agent (given by the SSH_AGENT_PID)
# -t life Set a default value for the maximum lifetime of identities added to the agent.

# Run SSH agent
ssh-agent
SSH_AUTH_SOCK=/tmp/ssh-XXXXXXscGOCq/agent.5285; export SSH_AUTH_SOCK;
SSH_AGENT_PID=5656; export SSH_AGENT_PID;
```

#### ssh-add

```bash
# OPTIONS:
# -X Unlock the agent
# -x Lock the agent with a password
# -L Lists public key parameters of all identities currently represented by the agent
# -l Lists fingerprints of all identities currently represented by the agent
# -D Deletes all identities from the agent
# -d Removes identities from the agent.

# Add SSH key to SSH agent
ssh-add
ssh-add -l
ssh-add -d
ssh-add -D
```

## openssh-server

```bash
# Install openssh-server
apt search openssh-server
apt info openssh-server
sudo apt install openssh-server

# The following NEW packages will be installed:
#   libwrap0 ncurses-term openssh-server openssh-sftp-server ssh-import-id

# Setting up openssh-server (1:8.9p1-3ubuntu0.10) ...

# Creating config file /etc/ssh/sshd_config with new version
# Creating SSH2 RSA key; this may take some time ...
# 3072 SHA256:2z6JcjWehBskWfx0NOPMSkbovJO3DjGKWNOuG5Cxc8c root@KL52-DEV01 (RSA)
# Creating SSH2 ECDSA key; this may take some time ...
# 256 SHA256:NauMNf4wI0hWIan4rHnuVL9WLgCRSoiWteUg0bsDbpk root@KL52-DEV01 (ECDSA)
# Creating SSH2 ED25519 key; this may take some time ...
# 256 SHA256:Ug/c697CRY1/ZY9rZ88xzP36Qogm5qIhe+Ypxb3qq+c root@KL52-DEV01 (ED25519)
# Created symlink /etc/systemd/system/sshd.service → /lib/systemd/system/ssh.service.
# Created symlink /etc/systemd/system/multi-user.target.wants/ssh.service → /lib/systemd/system/ssh.service.
# rescue-ssh.target is a disabled or a static unit, not starting it.
# ssh.socket is a disabled or a static unit, not starting it.
# Processing triggers for ufw (0.36.1-4ubuntu0.1) ...
# Processing triggers for man-db (2.10.2-1) ...
# Processing triggers for libc-bin (2.35-0ubuntu3.8) ...
```

> /etc/ufw/applications.d/openssh-server

```bash
# cat /etc/ufw/applications.d/openssh-server
[OpenSSH]
title=Secure shell server, an rshd replacement
description=OpenSSH is a free implementation of the Secure Shell protocol.
ports=22/tcp
```

> /etc/systemd/system/sshd.service

```bash
# ls -l /etc/systemd/system/sshd.service
# cat /etc/systemd/system/sshd.service
# cat /lib/systemd/system/ssh.service
[Unit]
Description=OpenBSD Secure Shell server
Documentation=man:sshd(8) man:sshd_config(5)
After=network.target auditd.service
ConditionPathExists=!/etc/ssh/sshd_not_to_be_run

[Service]
EnvironmentFile=-/etc/default/ssh
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
ExecReload=/usr/sbin/sshd -t
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255
Type=notify
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
Alias=sshd.service
```

> /etc/systemd/system/multi-user.target.wants/ssh.service

```bash
ls -l /etc/systemd/system/
ls -l /etc/systemd/system/multi-user.target.wants/ssh.service
```

## ufw firewall

```bash
systemctl list-units --type=service | grep ufw
systemctl status ufw
sudo ufw status

systemctl list-units --type=service | grep ssh
systemctl status sshd
telnet 127.0.0.1 22 # CTRL-] + quit or CTRL-z + ENTER

sudo ufw status
sudo ufw reload
sudo ufw enable

systemctl status sshd
sudo ufw status verbose
sudo ufw show added

sudo ufw app list
sudo ufw app info 'OpenSSH'
cut /etc/ufw/applications.d/openssh-server
sudo ufw allow OpenSSH
sudo iptables -S                    # list rules
sudo iptables -S | grep 22
sudo iptables -L                    # list rules in all chains
sudo iptables -L -n | grep 22
sudo iptables -L INPUT              # list all targets for INPUT chain
sudo iptables -n -L ufw-user-input  # list ufw chain
# sudo ufw allow 22/tcp
# sudo ufw allow from 192.168.1.1 to any port 22
# sudo ufw allow from 192.168.1.0/24 to any port 22
# sudo ufw allow in on eth2 to any port 22
# sudo ufw delete 1
# sudo ufw delete allow 443

sudo ufw status numbered
sudo iptables -S
sudo iptables -L -v -n
```

> cat /etc/default/ufw

```bash
cat /etc/default/ufw
```

> /lib/systemd/system/ufw.service

```bash
cat /lib/systemd/system/ufw.service
```

## Information sources

- [What is the Secure Shell (SSH) protocol?](https://www.cloudflare.com/en-gb/learning/access-management/what-is-ssh/)
- [How To: Inspect SSH Key Fingerprints](https://www.unixtutorial.org/how-to-inspect-ssh-key-fingerprints/)
- [Checking ssh public key fingerprints](https://www.phcomp.co.uk/Tutorials/Unix-And-Linux/ssh-check-server-fingerprint.html)
- [How to List UFW firewall rules on Linux](https://www.cyberciti.biz/faq/how-to-list-ufw-firewall-rules-on-linux/)
