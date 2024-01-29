# Oxide Helios: Image Boot Tools

Oxide computers boot from ramdisk images, obtained from a variety of sources
depending on the context in which the computer is presently operating.  The
ramdisk image contains a small ZFS pool, assembled by
[illumos/image-builder](https://github.com/illumos/image-builder) at the
direction of the `helios-build` tool in
[oxidecomputer/helios](https://github.com/oxidecomputer/helios).  This
repository contains tools for compressing those ramdisk image contents with an
metadata appropriate header, for inspecting images that exist already, and for
serving them over a local network.

Several components depend on the image format with which these tools operate:

- On production Oxide systems, the ramdisk image is loaded at boot from an
  internal NVMe device.  This is implemented in
  [uts/oxide/boot_image/oxide_boot_disk.c](https://github.com/oxidecomputer/illumos-gate/blob/stlouis/usr/src/uts/oxide/boot_image/oxide_boot_disk.c)
  in the operating system itself.  In this context the ramdisk image is often
  described as the "phase 2" image; the Host OS ROM, a small NOR flash device,
  holds the "phase 1" image that corresponds with the ramdisk image.

- The `mkimage` program in this repository is used by the **Helios** build
  process as a step in assembling the final shipping OS image artefact.

- The `bootserver` program in this repository uses a local Ethernet device to
  listen for broadcasts from an Oxide compute sled that is attempting to boot
  from the network via a K.2 network card adapter.  The protocol used is
  described in some detail in a command in
  [uts/oxide/boot_image/oxide_boot_net.c](https://github.com/oxidecomputer/illumos-gate/blob/stlouis/usr/src/uts/oxide/boot_image/oxide_boot_net.c)
  in the operating system itself.

- The `lookimage` program in this repository can check that an image
  is intact, using the checksums in the header, and allows the user to
  inspect image metadata; e.g.,

  ```
  $ lookimage /ws/helios/image/output/zfs.img
  image name = testing-tar
  flags = 0x0 ((empty))
  data size = 838860800
  image size = 838860800
  target size = 4294967296
  image sum = c18d8f9ad39c04e5d84580e701ce5e36cc1a7dd13515639194ca4aecb01e17f0
  dataset name = rpool/ROOT/ramdisk
  ```

- [Omicron](https://github.com/oxidecomputer/omicron), the Oxide control
  plane, contains software that deploys these images onto Oxide compute sleds
  in an Oxide rack as part of software update and system recovery.

  When a compute sled is unable to boot from local storage, a recovery image as
  created by these tools is sent by **Omicron** via the [Management Gateway
  Service (MGS)](https://github.com/oxidecomputer/management-gateway-service)
  to the **service processor (SP)** of the target sled, via the local
  management network.  The **SP** runs
  [Hubris](https://github.com/oxidecomputer/hubris), and is capable of
  forwarding the image to the host CPU via an internal UART (using **IPCC**)
  for boot.

  Comments describing the recovery protocol appear in
  [uts/oxide/boot_image/oxide_boot_sp.h](https://github.com/oxidecomputer/illumos-gate/blob/stlouis/usr/src/uts/oxide/boot_image/oxide_boot_sp.h)
  and
  [uts/oxide/boot_image/oxide_boot_sp.c](https://github.com/oxidecomputer/illumos-gate/blob/stlouis/usr/src/uts/oxide/boot_image/oxide_boot_sp.c).

## Licence

Copyright 2024 Oxide Computer Company

Unless otherwise noted, all components are licenced under the [Mozilla Public
License Version 2.0](./LICENSE).
