# SilentTrinity container 

For Windows targets

Dockerfile to start the SILENTTRINITY team server `~/SILENTTRINITY/Dockerfile`

```text
# The base Docker image containing binaries to run Python 3.7
FROM python:stretch-slim-3.7

# Install git, make, and gcc tools
RUN apt-get update && apt-get install -y git make gcc

# Download SILENTTRINITY and change directories
RUN git clone https://github.com/byt3bl33d3r/SILENTTRINITY/ /root/st/
WORKDIR /root/st/

# Install the Python requirements
RUN python3 -m pip install -r requirements.txt

# Inform future Docker users that they need to bind port 5000
EXPOSE 5000

# ENTRYPOINT is the first command the container runs when it starts
ENTRYPOINT ["python3", "teamserver.py", "0.0.0.0", "stringpassword"]
```

To pull the base image, populate it with the tools and files we mentioned, and name the resulting image silent:

    # docker build -t silent .

Start the newly built image in the background using the -d switch:

```text
root@tardis:~/# docker run -d \
-v /opt/st:/root/st/data \
-p5000:5000 \
silent
```

Connect to the team server running on the container:

```text
root@tardis:~/# python3.7 st.py \
wss://username:strongPasswordCantGuess@192.168.1.29:5000
```

To be able to download it from any workstation, push it to a Docker repository:

```text
root@tardis:~/# docker login
Username: barzh
Password:
Login Succeeded
root@tardis:~/# docker tag silent barzh/silent
root@tardis:~/# docker push barzh/silent
```

The SILENTTRINITY Docker image can now be pulled for running on any Linux machine spawned in the future.