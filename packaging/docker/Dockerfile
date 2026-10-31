# RMMZit server as a container image. It is built from the signed server
# package of a release (the same files as the appliance and the Linux
# packages), including the agent installers the console offers:
#
#   docker build --build-arg VERSION=0.13.0 -t rmmzit:0.13.0 .
#
# with rmmzit-server_<VERSION>_amd64.deb in this folder. The image holds only
# the server (a static program), CA certificates and time zones - no shell
# or system tools - and runs as the unprivileged user 10001.
FROM debian:bookworm-slim AS package
ARG VERSION
COPY rmmzit-server_${VERSION}_amd64.deb /tmp/server.deb
RUN dpkg-deb -x /tmp/server.deb /pkg \
 && install -d -m 0700 -o 10001 -g 10001 /pkg/var/lib/rmmzit

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION
LABEL org.opencontainers.image.title="RMMZit" \
      org.opencontainers.image.description="RMMZit server: self-hosted remote monitoring and management for Windows and Linux computers" \
      org.opencontainers.image.source="https://github.com/Max-Zit/rmmzit" \
      org.opencontainers.image.vendor="MaxZit" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.version="${VERSION}"
COPY --from=package /pkg/usr/bin/rmmzit-server /usr/bin/rmmzit-server
COPY --from=package /pkg/usr/share/rmmzit/downloads /usr/share/rmmzit/downloads
COPY --from=package /pkg/usr/share/doc/rmmzit-server /usr/share/doc/rmmzit-server
COPY --from=package --chown=10001:10001 /pkg/var/lib/rmmzit /var/lib/rmmzit
ENV RMMZIT_CONTAINER=docker \
    RMMZIT_DATA=/var/lib/rmmzit \
    HOME=/var/lib/rmmzit
USER 10001:10001
WORKDIR /var/lib/rmmzit
VOLUME /var/lib/rmmzit
# 8443: the console (web interface and API); 8444: the agent endpoint.
EXPOSE 8443 8444
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s \
  CMD ["/usr/bin/rmmzit-server", "-healthcheck"]
ENTRYPOINT ["/usr/bin/rmmzit-server"]
