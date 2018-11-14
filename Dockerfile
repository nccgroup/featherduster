FROM ubuntu:xenial

RUN apt-get update -qq && apt-get install -qq \
        build-essential \
        libncurses-dev \
        python-crypto \
        python-dev \
        python-pip \
        python-setuptools \
    && rm -rf /var/lib/apt/lists/*

COPY . /opt/featherduster
WORKDIR /opt/featherduster
RUN pip install -U pip
RUN pip install .

ENTRYPOINT ["python", "/opt/featherduster/featherduster/featherduster.py"]
