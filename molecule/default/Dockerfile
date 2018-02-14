# NOTE: This is only used if you are doing delegated builds in molecule that require you to docker exec inside
FROM ubuntu:14.04

ENV GOSS_VERSION=v0.3.5

RUN apt-get -y update && apt-get install -y python rsync sudo bash \
    devscripts git curl aptitude ipython libssl-dev ntp \
    python-dev python-pip python-ipdb ruby tmux vim paxctl && \
    aptitude -y dist-upgrade && \
    apt-get clean && \
    # Add goss for local, serverspec-like testing
    curl -L https://github.com/aelsabbahy/goss/releases/download/${GOSS_VERSION}/goss-linux-amd64 -o /usr/local/bin/goss && \
    chmod +x /usr/local/bin/goss
