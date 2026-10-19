FROM docker.io/library/debian@sha256:918311b7b6c4c6f68b232ba516584925f6c78ad82b6fd534b98979df6438e483

# Context is an explicit public-input staging directory, never the repository,
# private device state, Docker socket, SSH home or signing-key tree.
COPY repository/ /repository/
COPY packages.txt /packages.txt
COPY build.sh /build.sh
RUN /bin/sh /build.sh

ENV PYTHONDONTWRITEBYTECODE=1
CMD ["/usr/bin/mkosi", "--version"]
