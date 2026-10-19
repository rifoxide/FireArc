#!/bin/sh
set -eu

# Fresh container only. No host devices/mounts/network/privileged build mode.
export DEBIAN_FRONTEND=noninteractive
export APT_CONFIG=/repository/apt.conf
export LC_ALL=C

mkdir -p /work/apt/apt.conf.d /work/state/lists/partial /work/cache/archives/partial /work/log
cp /repository/sources.list /work/apt/sources.list
# Debian packages must not start services or generate device identities here.
printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
chmod 0755 /usr/sbin/policy-rc.d

apt-get update
xargs -r -a /packages.txt apt-get --yes --no-install-recommends install
dpkg --audit
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' > /tool-packages.tsv

# No keys are generated. In particular, do not run mkosi genkey or swtpm_setup.
mkosi --version
/usr/lib/systemd/systemd-measure --version
/usr/lib/systemd/ukify --version
rauc --version
