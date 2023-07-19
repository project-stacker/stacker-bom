load helpers

function setup() {
  common_setup
  zot_setup
}

function teardown() {
  zot_teardown
  common_teardown
}

@test "bom workflow" {
  # inventory
  docker run -v ${TOPDIR}/bin:/opt/bin -v ${BOMD}:/stacker-artifacts -i ubuntu:latest /opt/bin/stacker-bom-linux-amd64 inventory -x /proc,/sys,/dev,/tmp,/opt,/var/lib/dpkg/info,/var/log,/var/cache,/var/lib/systemd,/var/lib/dpkg,/var/lib/apt,/var/lib/pam,/var/lib/shells.state,/.dockerenv,/usr/share/info,/usr/sbin/policy-rc.d,/etc,/run,/root,/usr/bin/man,/usr/local/sbin/unminimize,/usr/sbin/initctl,/stacker-artifacts -o /stacker-artifacts/inventory.json
  [ -f ${BOMD}/inventory.json ]
  # discover installed packages
  docker run -v ${TOPDIR}/bin:/opt/bin -v ${BOMD}:/stacker-artifacts -i ubuntu:latest /opt/bin/stacker-bom-linux-amd64 discover -o /stacker-artifacts/discover.json
  [ -f ${BOMD}/discover.json ]
  # verify against inventory
  ${TOPDIR}/bin/stacker-bom-linux-amd64 verify -i ${BOMD}/discover.json -t ${BOMD}/inventory.json -m ${BOMD}/missing.json
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
