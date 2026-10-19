#!/bin/sh
# Trusted initrd library. Never source/eval disk-provided authority or cmdline.

fa_load_authority() {
    local file=$1 line key value seen='|'
    FA_SLOT= FA_ROOT_HASH= FA_SALT=
    [ -f "$file" ] && [ ! -L "$file" ] || return 1
    [ "$(stat -c %s "$file")" -le 4096 ] || return 1
    # grep -a also rejects NUL/non-ASCII, which shell read could otherwise lose.
    if LC_ALL=C grep -aq '[^a-zA-Z0-9_=]' "$file"; then return 1; fi
    while IFS= read -r line || [ -n "$line" ]; do
        key=${line%%=*}
        value=${line#*=}
        [ "$line" != "$key" ] || return 1
        case "$seen" in *"|$key|"*) return 1 ;; esac
        case "$key" in
            root_hash|salt)
                [ "${#value}" -eq 64 ] || return 1
                case "$value" in *[!0-9a-f]*) return 1 ;; esac
                if [ "$key" = root_hash ]; then FA_ROOT_HASH=$value; else FA_SALT=$value; fi ;;
            slot) case "$value" in A|B) FA_SLOT=$value ;; *) return 1 ;; esac ;;
            *)
                case "$line" in
                    schema=1|layout_version=1|format=1|algorithm=sha256|data_bytes=4294967296|data_blocks=1048576|data_block_size=4096|hash_bytes=134217728|hash_block_size=4096|hash_offset=0) ;;
                    *) return 1 ;;
                esac ;;
        esac
        seen="$seen$key|"
    done < "$file"
    for key in schema layout_version slot root_hash salt format algorithm data_bytes data_blocks data_block_size hash_bytes hash_block_size hash_offset; do
        case "$seen" in *"|$key|"*) ;; *) return 1 ;; esac
    done
}

fa_is_block() { [ -b "$1" ]; }

fa_check_cmdline() {
    local content token key seen='|'
    content=$(cat "$1") || return 1
    [ "${#content}" -le 8192 ] || return 1
    set -f
    for token in $content; do
        key=
        case "$token" in
            root=/dev/mapper/firearc-root) key=root ;;
            rootfstype=ext4) key=rootfstype ;;
            rootflags=ro,noload) key=rootflags ;;
            ro) key=ro ;;
            rauc.slot=*) [ "$token" = "rauc.slot=$FA_SLOT" ] || return 1; key=slot ;;
            rd.shell=0) key=shell ;;
            rd.emergency=poweroff) key=emergency ;;
            root=*|rootfstype=*|rootflags=*|rw|rd.shell=*|rd.emergency=*|init=*|rdinit=*|systemd.unit=*|rd.systemd.unit=*|systemd.debug_shell*|rd.systemd.debug_shell*|rd.break*) return 1 ;;
        esac
        if [ -n "$key" ]; then
            case "$seen" in *"|$key|"*) return 1 ;; esac
            seen="$seen$key|"
        fi
    done
    for key in root rootfstype rootflags ro slot shell emergency; do
        case "$seen" in *"|$key|"*) ;; *) return 1 ;; esac
    done
}

fa_unique_label() {
    local device
    device=$(blkid -c /dev/null -t "PARTLABEL=$1" -o device) || return 1
    case "$device" in /dev/*) ;; *) return 1 ;; esac
    # A newline, whitespace or shell syntax also rejects multiple matches.
    case "$device" in *[!a-zA-Z0-9/_-]*) return 1 ;; esac
    fa_is_block "$device" || return 1
    [ "$(lsblk -dn -o TYPE "$device")" = part ] || return 1
    printf '%s\n' "$device"
}

fa_parent_disk() {
    local parent
    parent=$(lsblk -dn -o PKNAME "$1") || return 1
    [ -n "$parent" ] || return 1
    case "$parent" in *[!a-zA-Z0-9_-]*) return 1 ;; esac
    [ "$(lsblk -dn -o TYPE "/dev/$parent")" = disk ] || return 1
    printf '%s\n' "$parent"
}

fa_select_devices() {
    local root_parent hash_parent esp_parent
    case "$FA_SLOT" in A|B) ;; *) return 1 ;; esac
    FA_ROOT_DEVICE=$(fa_unique_label "FIREARC_ROOT_$FA_SLOT") || return 1
    FA_HASH_DEVICE=$(fa_unique_label "FIREARC_HASH_$FA_SLOT") || return 1
    FA_ESP_DEVICE=$(fa_unique_label FIREARC_ESP) || return 1
    [ "$FA_ROOT_DEVICE" != "$FA_HASH_DEVICE" ] && [ "$FA_ROOT_DEVICE" != "$FA_ESP_DEVICE" ] && [ "$FA_HASH_DEVICE" != "$FA_ESP_DEVICE" ] || return 1
    root_parent=$(fa_parent_disk "$FA_ROOT_DEVICE") || return 1
    hash_parent=$(fa_parent_disk "$FA_HASH_DEVICE") || return 1
    esp_parent=$(fa_parent_disk "$FA_ESP_DEVICE") || return 1
    [ "$root_parent" = "$hash_parent" ] && [ "$root_parent" = "$esp_parent" ] || return 1
    [ "$(blockdev --getsize64 "$FA_ROOT_DEVICE")" = 4294967296 ] || return 1
    [ "$(blockdev --getsize64 "$FA_HASH_DEVICE")" = 134217728 ] || return 1
}

fa_check_boot_esp() {
    local uuid actual expected
    uuid=$(blkid -p -s PART_ENTRY_UUID -o value "$FA_ESP_DEVICE") || return 1
    [ "${#uuid}" -eq 36 ] || return 1
    case "$uuid" in ????????-????-????-????-????????????) ;; *) return 1 ;; esac
    case "$uuid" in *[!0-9a-f-]*) return 1 ;; esac
    # Compare the boot loader's UTF-16LE UUID, including terminator, without
    # evaluating/decoding variable contents into shell syntax.
    actual=$(od -An -v -tx1 -j4 /sys/firmware/efi/efivars/LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f | tr -d ' \n') || return 1
    expected=$(printf '%s' "$uuid" | od -An -v -tx1 | tr -d ' \n' | sed 's/../&00/g')0000
    [ "${#actual}" -eq 148 ] && [ "${#expected}" -eq 148 ] || return 1
    [ "$actual" = "$expected" ]
}

fa_mapping_absent() { [ ! -e /dev/mapper/firearc-root ] && [ ! -L /dev/mapper/firearc-root ]; }

fa_verify_and_open() {
    fa_mapping_absent || return 1
    blockdev --setro "$FA_ROOT_DEVICE" || return 1
    blockdev --setro "$FA_HASH_DEVICE" || return 1
    # All geometry comes from the validated embedded authority/format contract.
    veritysetup verify "$FA_ROOT_DEVICE" "$FA_HASH_DEVICE" "$FA_ROOT_HASH" \
        --no-superblock --format=1 --hash=sha256 --data-blocks=1048576 \
        --data-block-size=4096 --hash-block-size=4096 --hash-offset=0 --salt="$FA_SALT" || return 1
    echo FIREARC_VERITY_PREVERIFY_OK
    veritysetup open "$FA_ROOT_DEVICE" firearc-root "$FA_HASH_DEVICE" "$FA_ROOT_HASH" \
        --readonly --no-superblock --format=1 --hash=sha256 --data-blocks=1048576 \
        --data-block-size=4096 --hash-block-size=4096 --hash-offset=0 --salt="$FA_SALT" || return 1
    if [ "$(blockdev --getro /dev/mapper/firearc-root)" != 1 ] || [ "$(blockdev --getsize64 /dev/mapper/firearc-root)" != 4294967296 ]; then
        veritysetup close firearc-root || :
        return 1
    fi
    echo FIREARC_VERITY_MAPPING_READY
}
