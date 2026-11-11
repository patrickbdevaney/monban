# Monban cmvp build image (PLAN-6 D1/D6/D7, PREFLIGHT P2): Amazon Linux 2023, the only tested operational environment
# of AWS-LC FIPS 3.1.0 (CMVP #5298/#5314). The base is pinned by digest and the dnf repo snapshot by --releasever
# (the base image's own release, 2023.12.20261102, so installed packages match its glibc). One RUN layer; docs,
# locales and man pages are not installed or are removed. Go (~/aegis-ci/go1.27.3) and the Rust toolchain
# (~/aegis-ci/rustup) are mounted read-only at run time, never baked in. profiles/cmvp/build.sh asserts the image is
# < 500 MB.
FROM amazonlinux@sha256:bb1c85fe00170acd8a653de5f68cf77c7ec67234a130b18fad7ca1de1f61e3d3
RUN dnf --releasever=2023.12.20261102 --setopt=tsflags=nodocs --setopt=install_weak_deps=False -y install \
        gcc gcc-c++ cmake perl-interpreter perl-FindBin make findutils tar gzip \
    && dnf clean all \
    && rm -rf /var/cache/dnf /var/log/dnf* /usr/share/doc /usr/share/man /usr/share/info /usr/share/locale/* \
        /usr/lib/locale/locale-archive.tmpl
