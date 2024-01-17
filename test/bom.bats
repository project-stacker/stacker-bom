load helpers

function setup() {
  common_setup
  zot_setup
}

function teardown() {
  zot_teardown
  common_teardown
}

@test "deb bom workflow" {
  # inventory
  docker run -v ${TOPDIR}/bin:/opt/bin -v ${BOMD}:/stacker-artifacts -i ubuntu:latest /opt/bin/stacker-bom-linux-amd64 inventory -x /proc,/sys,/dev,/tmp,/opt,/var/lib/dpkg/info,/var/log,/var/cache,/var/lib/systemd,/var/lib/dpkg,/var/lib/apt,/var/lib/pam,/var/lib/shells.state,/.dockerenv,/usr/share/info,/usr/sbin/policy-rc.d,/etc,/run,/root,/usr/bin/man,/usr/local/sbin/unminimize,/usr/sbin/initctl,/stacker-artifacts -o /stacker-artifacts/inventory.json
  [ -f ${BOMD}/inventory.json ]
  # discover installed packages
  docker run -v ${TOPDIR}/bin:/opt/bin -v ${BOMD}:/stacker-artifacts -i ubuntu:latest /opt/bin/stacker-bom-linux-amd64 discover -o /stacker-artifacts/discover.json
  [ -f ${BOMD}/discover.json ]
  # verify against inventory
  docker run -v ${TOPDIR}/bin:/opt/bin -v ${BOMD}:/stacker-artifacts -i ubuntu:latest /opt/bin/stacker-bom-linux-amd64 verify -i /stacker-artifacts/discover.json -t  /stacker-artifacts/inventory.json -m  /stacker-artifacts/missing.json
  [ ! -f ${BOMD}/missing.json ]
  # push the image
  skopeo copy --format=oci --dest-tls-verify=false docker://ubuntu:latest docker://${ZOT_HOST}:${ZOT_PORT}/ubuntu:latest
  # validate the sbom
  bom document outline ${BOMD}/discover.json
  # attach bom artifacts as references
  regctl artifact put --artifact-type application/vnd.stacker-bom.inventory -f ${BOMD}/inventory.json --subject ${ZOT_HOST}:${ZOT_PORT}/ubuntu:latest
  regctl artifact put --artifact-type application/org.spdx+json -f ${BOMD}/discover.json --subject ${ZOT_HOST}:${ZOT_PORT}/ubuntu:latest
  regctl artifact tree ${ZOT_HOST}:${ZOT_PORT}/ubuntu:latest
}

@test "apk bom workflow" {
  # inventory
  docker run -v ${TOPDIR}/bin:/opt/bin -v ${BOMD}:/stacker-artifacts -i alpine:edge /opt/bin/stacker-bom-linux-amd64 inventory -x /proc,/sys,/dev,/tmp,/opt,/lib/apk/db,/var/log,/var/cache,/var/lib/systemd,/var/lib/pam,/var/lib/shells.state,/.dockerenv,/usr/share/info,/usr/sbin/policy-rc.d,/etc,/run,/root,/usr/bin/man,/usr/local/sbin/unminimize,/usr/sbin/initctl,/stacker-artifacts -o /stacker-artifacts/inventory.json
  [ -f ${BOMD}/inventory.json ]
  # discover installed packages
  docker run -v ${TOPDIR}/bin:/opt/bin -v ${BOMD}:/stacker-artifacts -i alpine:edge /opt/bin/stacker-bom-linux-amd64 discover -o /stacker-artifacts/discover.json
  [ -f ${BOMD}/discover.json ]
  # verify against inventory
  docker run -v ${TOPDIR}/bin:/opt/bin -v ${BOMD}:/stacker-artifacts -i alpine:edge /opt/bin/stacker-bom-linux-amd64 verify -i /stacker-artifacts/discover.json -t  /stacker-artifacts/inventory.json -m  /stacker-artifacts/missing.json
  [ ! -f ${BOMD}/missing.json ]
  # push the image
  skopeo copy --format=oci --dest-tls-verify=false docker://alpine:edge docker://${ZOT_HOST}:${ZOT_PORT}/alpine:edge
  # validate the sbom
  bom document outline ${BOMD}/discover.json
  # attach bom artifacts as references
  regctl artifact put --artifact-type application/vnd.stacker-bom.inventory -f ${BOMD}/inventory.json --subject ${ZOT_HOST}:${ZOT_PORT}/alpine:edge
  regctl artifact put --artifact-type application/org.spdx+json -f ${BOMD}/discover.json --subject ${ZOT_HOST}:${ZOT_PORT}/alpine:edge
  regctl artifact tree ${ZOT_HOST}:${ZOT_PORT}/alpine:edge
}

@test "rpm bom workflow" {
  # inventory
  docker run -v ${TOPDIR}/bin:/opt/bin -v ${BOMD}:/stacker-artifacts -i rockylinux:9 /opt/bin/stacker-bom-linux-amd64 inventory -x /proc,/sys,/dev,/tmp,/opt,/var/log,/var/lib/rpm,/var/lib/alternatives,/root,/etc,/.dockerenv,/stacker-artifacts -o /stacker-artifacts/inventory.json
  [ -f ${BOMD}/inventory.json ]
  # discover installed packages
  docker run -v ${TOPDIR}/bin:/opt/bin -v ${BOMD}:/stacker-artifacts -i rockylinux:9 /opt/bin/stacker-bom-linux-amd64 discover -o /stacker-artifacts/discover.json
  [ -f ${BOMD}/discover.json ]
  # verify against inventory
  docker run -v ${TOPDIR}/bin:/opt/bin -v ${BOMD}:/stacker-artifacts -i rockylinux:9 /opt/bin/stacker-bom-linux-amd64 verify -i /stacker-artifacts/discover.json -t  /stacker-artifacts/inventory.json -m  /stacker-artifacts/missing.json
  [ ! -f ${BOMD}/missing.json ]
  # push the image
  skopeo copy --format=oci --dest-tls-verify=false docker://rockylinux:9 docker://${ZOT_HOST}:${ZOT_PORT}/rockylinux:9
  # validate the sbom
  bom document outline ${BOMD}/discover.json
  # attach bom artifacts as references
  regctl artifact put --artifact-type application/vnd.stacker-bom.inventory -f ${BOMD}/inventory.json --subject ${ZOT_HOST}:${ZOT_PORT}/rockylinux:9
  regctl artifact put --artifact-type application/org.spdx+json -f ${BOMD}/discover.json --subject ${ZOT_HOST}:${ZOT_PORT}/rockylinux:9
  regctl artifact tree ${ZOT_HOST}:${ZOT_PORT}/rockylinux:9
}
