# Architecture Decisions

| Date | Decision | Why |
| --- | --- | --- |
| 2026-09-30 | Use the existing Pop!_OS 24.04/libvirt 10.0.0/Docker 29.1.3 installation as the M0 baseline. | These components are already installed and functional; avoiding alternate repositories reduces host drift. |
| 2026-09-30 | Do not provision until a dedicated `/srv/dfir` filesystem is supplied and mounted. | The root filesystem has about 39 GiB free, which is unsuitable for immutable evidence, VM disks, indexes, and PCAPs. |
| 2026-09-30 | Pin all application releases and record container digests and ISO checksums before deployment. | Reproducible processing and defensible evidence require immutable inputs rather than floating tags. |
| 2026-09-30 | Keep the existing libvirt `default` network and guests untouched unless a later approved milestone explicitly changes them. | They predate this project and are outside the requested isolated lab scope. |
| 2026-09-30 | Use the available Compose v2 binary rather than installing an unavailable apt `docker-compose-plugin` candidate. | The host already provides a working Compose v2 implementation; adding another package source is unnecessary risk. |
