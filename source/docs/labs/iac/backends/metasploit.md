# Metasploit container 

For Linux and macOS targets.

## Installation

* [Install Docker Desktop on Linux](https://docs.docker.com/desktop/install/linux-install/)
* [Pull the phocean/msf Docker image](https://hub.docker.com/r/phocean/msf/#!) 
* The image contains Metasploit files, binaries, and dependencies that are already compiled 
and ready to go. Run it:

```text
docker run --rm -it phocean/msf
```

The `--rm` option deletes the container upon termination to clean up resources. 
The `-it` option allocates a pseudoterminal and links to the container’s stdin device to mimic an interactive shell.

* Start Metasploit using the msfconsole command:

```text
:/opt/metasploit-framework# ./msfconsole
```

### Preps for connecting to the frontend

When starting a container, Docker automatically creates a pair of virtual Ethernet devices. One end is assigned the 
new namespace, where it can be used by the container to send and receive network packets. The other connector is 
assigned the default namespace and is plugged into a network switch that carries traffic to and from the external 
world. Linux calls this virtual switch a network bridge.

An `ip addr | grep "docker0"` on the ubuntu host machine shows the default `docker0` bridge with
the allocated 172.17.0.0/16 or 172.17.0.0/16 IP range ready to be distributed across new
containers.

Every container gets its dedicated veth pair, and therefore IP address, from the `docker0` bridge IP range.

```text
$ sudo docker run --rm \
-it -p 8400-8500:8400-8500 \
-v ~/.msf4:/root/.msf4 \
-v /tmp/msf:/tmp/data \
phocean/msf
```

A handler listening on any port between 8400 and 8500 inside the container can be reached by sending packets to the 
host’s IP address on that same port range.

Mapping the `~/.msf4` and `/tmp/msf` directories on the host to directories in the container, `/root/.msf4` and `/tmp/`
data is for persisting data across multiple runs of the same Metasploit container.

To send the container to the background, press `CTRL-P` followed by `CTRL-Q`. 
Or send it to the background from the start by adding the `-d` flag. To get inside again, execute a 
`docker ps`, get the Docker ID, and run `docker attach <ID>`. Or run the docker `exec -it <ID> sh` command.
