# Remote docker environment for ztunnel development.
#
# Build:
#   docker build -t ztunnel/remote-env:0.1 -f docker/remote-env/Dockerfile .
#
# Run:
#   docker run -d \
#       --privileged \
#       -p 127.0.0.1:2222:22 \
#       --name ztunnel-dev \
#       --mount type=bind,source="$PWD",target="/home/user/ztunnel" \
#       ztunnel/remote-env:0.1
#
# Clear credentials:
#   ssh-keygen -f "$HOME/.ssh/known_hosts" -R "[localhost]:2222"
#
# stop:
#   docker stop ztunnel-dev
#
# ssh credentials (test user):
#   ssh user@localhost -p2222 (enter `password` on the command-line)

FROM gcr.io/istio-testing/build-tools:master-65b95c3425a26e633081b2d0834cc0df6e81fd8a

# - git (and git-lfs), for git operations (to e.g. push your work).
#   Also required for setting up your configured dotfiles in the workspace.
# - sudo, while not required, is recommended to be installed, since the
#   workspace user (`gitpod`) is non-root and won't be able to install
#   and use `sudo` to install any other tools in a live workspace.
RUN apt-get update && apt-get install --no-install-recommends -yq \
    net-tools \
    iproute2 \
    iptables \
    cmake \
    ninja-build \
    git \
    sudo \
    ssh \
    && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/*

# Add the rust source code and set up the environment.
RUN rustup component add rust-src
ENV CARGO_HOME="/home/.cargo"
ENV RUSTUP_HOME="/home/.rustup"
ENV PATH=$CARGO_HOME/bin:$PATH

# Create the configuration file for sshd
RUN ( \
    echo 'LogLevel DEBUG2'; \
    echo 'PermitRootLogin yes'; \
    echo 'PasswordAuthentication yes'; \
    echo 'AllowTcpForwarding yes'; \
    echo 'Subsystem sftp /usr/lib/openssh/sftp-server'; \
  ) > /etc/ssh/sshd_remote_dev \
  && mkdir /run/sshd

# Add remote user with a plaintext password.
ARG REMOTE_USER=user
ARG REMOTE_USER_PASSWORD=password
ARG REMOTE_USER_HOME=/home/$REMOTE_USER
ARG REMOTE_USER_SHELL=/bin/bash
ARG REMOTE_USER_LOGIN_SCRIPT=$REMOTE_USER_HOME/.bashrc
ARG REMOTE_USER_ID=3333
ARG REMOTE_USER_GROUPS=sudo
# ignoring because the current shell doesn't support pipefail; likely want to have a better fix long term
# hadolint ignore=DL4006
RUN useradd -lm \
  -u $REMOTE_USER_ID \
  -G $REMOTE_USER_GROUPS \
  -d $REMOTE_USER_HOME \
  -s $REMOTE_USER_SHELL \
  $REMOTE_USER \
  && yes $REMOTE_USER_PASSWORD | passwd $REMOTE_USER

# Set the rust environment in the remote user login script.
RUN echo "export CARGO_HOME=$CARGO_HOME" >> $REMOTE_USER_LOGIN_SCRIPT
RUN echo "export RUSTUP_HOME=$RUSTUP_HOME" >> $REMOTE_USER_LOGIN_SCRIPT
RUN echo "export PATH=$PATH" >> $REMOTE_USER_LOGIN_SCRIPT

ENV BUILD_WITH_CONTAINER=0
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e", "-f", "/etc/ssh/sshd_remote_dev"]