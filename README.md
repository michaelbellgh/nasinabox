# nasinabox
## _Automatic portable NAS creator using Ansible_



nasinabox is a portable NAS that can run in a VM or physical machine. Users can access it on the local network using [hostname.local]


## Features

- Homer dashboard built in, providing a landing page for users
- A suite of automatic TV, movies, books, music and subtitle downloaders
- Auto configured Torznab indexer for torrent downloads
- Pre configured Deluge torrent frontend and daemon
- Plex container ready to be used on local network
- Auto configuration of the downloaders, indexers and torrent client

## Installation

nasinabox is designed to configure a blank, Ubuntu server image. 
This should be deployed in advance, with two hard drives.


The recommended version of Ubuntu is 22.04 Server with the minimized install
8GB of RAM, 4 CPU cores is recommended, with a 100GB HDD and a secondary larger storage drive

First, copy the following templates into new locations:
> cp data/vars/vm.yml.example data/vars/vm.yml
> cp inventory/standalone.example inventory/standalone

Edit the above files to match your installation, e.g. if your details for your server were:
> hostname: nasinabox
> username: myname
> password: mypassword
> my sudo password: mypassword
> host/IP address: 192.168.1.50

Set the values in inventory/standalone as:
```
[nas]
192.168.1.50 ansible_become_password=mypassword ansible_user=nasinabox ansible_password=mypassword
```

Set the values in data/vars/vm.yml as:
```
creds: {guest_pass: nasinabox, guest_user: nasinabox}
api_key: "4nnuqufdm909hthay5rnu0fq8mbix36j"
vminfo:
    hostname: nasinabox
```

Finally, run the playbook using ansible against the target host
```
ansible-playbook -i inventory/standalone plays/nasinabox.yml
```

## Usage
To start using the NAS, navigate to hostname.local, where hostname = the hostname of your Ubuntu machine. 
This will only work on the locally connected network.

## Technologies
This project only has custom ansible playbooks and python configuration scripts - the actual hard work is done by many other developers, namely:
- Sonarr - TV Downloader (https://sonarr.tv/) running on docker container by LinuxServer (https://hub.docker.com/r/linuxserver/sonarr)
- Radarr - Movie Downloader (https://radarr.video/) running on docker container by LinuxServer (https://hub.docker.com/r/linuxserver/radarr)
- Lidarr - Music Downloader (https://lidarr.audio/) running on docker container by LinuxServer (https://hub.docker.com/r/linuxserver/lidarr)
- Readarr - Book Downloader (https://readarr.com/) running on docker container by LinuxServer (https://hub.docker.com/r/linuxserver/readarr)
- Homer - Dashboard (https://github.com/bastienwirtz/homer) running on docker container by LinuxServer (https://hub.docker.com/r/b4bz/homer)
- Deluge - Torrent client (https://dev.deluge-torrent.org/wiki/Download) running on docker container by LinuxServer (https://hub.docker.com/r/linuxserver/deluge)
- Traefik - Reverse Proxy (https://traefik.io/) running on official docker container (https://hub.docker.com/_/traefik)
- Jackett - Torznab torrent indexer (https://github.com/Jackett/Jackett) running on docker container by LinuxServer (https://hub.docker.com/r/linuxserver/jackett)
- Samba - SMB server (https://www.samba.org/) running on docker container by dperson (https://hub.docker.com/r/dperson/samba)
- Plex - Media player and server (https://www.plex.tv/) running on docker container by LinuxServer (https://hub.docker.com/r/linuxserver/plex)
- Ombi - Plex and downloader (sonarr, radarr, lidarr) request frontend (https://ombi.io/) running on docker container by LinuxServer (https://hub.docker.com/r/linuxserver/ombi/)

In addition to the above docker contaners, the configuration script (data/scripts/configure_apps.py) is included as part of this repo and will automatically configure the included applications to integrate with each other. 
The exception to this is Ombi and Plex, as they require manual configuration with Plex credentials

## SSL Certificate Warning
By default, the ansible playbook will generate a new self signed cert.
You can replace this with your own certificate (cn = hostname.local, SAN = DNS: hostname.local)
You can also install this certificate as a Trusted Root certficate to remove certificate errors.
