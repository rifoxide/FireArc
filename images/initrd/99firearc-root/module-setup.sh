#!/bin/bash
check() { return 0; }
depends() { echo 'systemd systemd-initrd dm kernel-modules'; }

installkernel() {
    instmods dm_mod dm_verity ext4 virtio_pci virtio_blk virtio_scsi sd_mod
}

install() {
    inst_multiple veritysetup blkid lsblk blockdev stat grep od tr sed cat udevadm sleep
    inst_simple "$moddir/authority.sh" /usr/lib/firearc/authority.sh
    inst_script "$moddir/firearc-verify-root" /usr/lib/firearc/verify-root
    chmod 0755 "$initdir/usr/lib/firearc/verify-root"
    local unit generator
    for unit in firearc-verify-root.service firearc-boot-failure.service sysroot.mount emergency.target; do
        inst_simple "$moddir/$unit" "/etc/systemd/system/$unit"
    done
    ln -sf emergency.target "$initdir/etc/systemd/system/rescue.target"
    mkdir -p "$initdir/etc/systemd/system/initrd-root-fs.target.requires" "$initdir/etc/systemd/system-generators"
    ln -s ../sysroot.mount "$initdir/etc/systemd/system/initrd-root-fs.target.requires/sysroot.mount"
    ln -sf /usr/lib/systemd/system/initrd.target "$initdir/etc/systemd/system/default.target"
    for unit in emergency.service rescue.service debug-shell.service; do
        ln -sf /dev/null "$initdir/etc/systemd/system/$unit"
    done
    # These initrd-only masks prevent automatic raw-root or alternate-verity
    # generators from racing the explicit, higher-priority sysroot mount.
    for generator in systemd-gpt-auto-generator systemd-fstab-generator systemd-veritysetup-generator dracut-rootfs-generator systemd-debug-generator; do
        ln -sf /dev/null "$initdir/etc/systemd/system-generators/$generator"
    done
    # Authority is intentionally NOT taken from the build host or root disk.
    # Slot authority is added to the UKI initrd only after root bytes are frozen.
}
