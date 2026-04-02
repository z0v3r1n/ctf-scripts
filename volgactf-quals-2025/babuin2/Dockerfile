FROM archlinux/archlinux:base-devel-20260327.0.506592@sha256:9ef351c3666a4f9246a113f791d85dff56714e897bcffeeda1a7760e6a3820aa AS archlinux

RUN pacman --noconfirm -Suy libepoxy qemu-system-x86

FROM pwn.red/jail as jail
COPY --from=archlinux / /srv

RUN mkdir -p /srv/app
COPY bzImage /srv/app/bzImage
RUN chmod ugo+rx /srv/app/bzImage && chmod ugo-w /srv/app/bzImage
COPY initramfs.cpio.gz /srv/app/initramfs.cpio.gz
RUN chmod ugo+rx /srv/app/initramfs.cpio.gz && chmod ugo-w /srv/app/initramfs.cpio.gz
COPY flag.txt /srv/app/flag.txt
RUN chmod ugo+rx /srv/app/flag.txt && chmod ugo-w /srv/app/flag.txt
COPY run.sh /srv/app/run
RUN chmod ugo+rx /srv/app/run && chmod ugo-w /srv/app/run

FROM scratch
COPY --from=jail / /

COPY setup_jail.sh /bin/setup_jail.sh
RUN chmod ugo+rx /bin/setup_jail.sh && chmod ugo-w /bin/setup_jail.sh

CMD ["/bin/setup_jail.sh"]
