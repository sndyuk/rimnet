FROM ubuntu:20.04

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y sudo build-essential wget htop vim less tree curl zip unzip git iputils-ping iproute2 \
  && rm -rf /var/lib/apt/lists/*

RUN addgroup wheel \
  && useradd --create-home --shell /bin/bash -G wheel rimnet \
  && echo 'auth sufficient pam_wheel.so trust group=wheel' >> /etc/pam.d/su \
  && echo '%wheel ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers

RUN sed -i '1s/^/force_color_prompt=yes\n/' /home/rimnet/.bashrc

USER rimnet
WORKDIR /home/rimnet

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.58.1
ENV PATH $PATH:/home/rimnet/.cargo/bin
RUN rustup install 1.58.1

CMD ["bash"]
