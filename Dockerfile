# Use the official Docker Hub Ubuntu 14.04 base image
FROM debian:jessie

#Update and install deps
RUN apt-get update && apt-get install -y \
        build-essential \
        git \ 
        libncurses-dev \
        libgmp3-dev \
        python-crypto \
        python-dev \
        python-setuptools \
    && rm -rf /var/lib/apt/lists/*

#Clone latest Featherduster
RUN git clone https://github.com/nccgroup/featherduster.git 
RUN mv featherduster /opt/. 
WORKDIR /opt/featherduster
RUN python setup.py install
COPY . .

# Load the entrypoint script to be run later
#RUN ["cd /opt/featherduster && python featherduster.py"]
ENTRYPOINT ["python", "/opt/featherduster/featherduster/featherduster.py"]
