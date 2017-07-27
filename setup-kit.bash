. "${BASH_SOURCE[0]%/*}/log-kit.bash"

log_all_input() {
    local log_tag="$1" log_line
    while IFS='' read -r log_line; do
	log "[$log_tag] $log_line"
    done
}

tmp_files=()
tmp=""

cleanup() {
    if [[ ${#tmp_files[@]} -ge 1 ]]; then
	rm -rf "${tmp_files[@]}"
    fi
}

trap cleanup EXIT

ensure_owner_mode() {
    local path="$1" owner="$2" mode="$3"
    [[ $owner =~ .:. ]] || arg_err "owner must have user:group form"

    local s
    s="$(stat -c "%U:%G:%a" "$path")"
    local current_owner="${s%:*}"
    local current_mode="${s##*:}"
    if [[ $owner != "$current_owner" ]]; then
	cmd_log chown "$owner" "$path"
    fi
    if let "0$current_mode != 0$mode"; then
	cmd_log chmod "=$mode" "$path"
    fi
}

ensure_dir() {
    local path="$1" owner="$2" mode="$3"
    [[ $owner =~ .:. ]] || arg_err "owner must have user:group form"

    [[ ! -h $path ]] || err "$path is a symbolic link"
    if [[ -e "$path" ]]; then
	[[ -d "$path" ]] || err "$path is not a directory"
	ensure_owner_mode "$path" "$owner" "$mode"
    else
	cmd_log mkdir -m "$mode" "$path"
	cmd_log chown "$owner" "$path"
    fi
}

ensure_fifo() {
    local path="$1"

    [[ ! -h $path ]] || err "$path is a symbolic link"
    if [[ -e "$path" ]]; then
	[[ -p "$path" ]] || err "$path is not a pipe"
    else
	cmd_log mkfifo "$path"
    fi
}

ensure_file_with_randoms() {
    local size path s
    size="$1"
    path="$2"

    if [[ ! -s "$path" ]]; then
	log "generating $size random bytes for $path"
	tmp_files+=("$path.tmp")
	dd if=/dev/urandom of="$path.tmp" bs="$size" count=1 status=none
	mv -fT "$path.tmp" "$path"
    fi
    s="$(find "$path" -maxdepth 0 -type f -size "${size}c")"
    [[ $s ]] || err "$path exists but its size is not $size."
}

generate_password() {
    dd if=/dev/urandom bs=1 count=12 status=none | base64 | sed -e 's/[+/]//'
}

run_gpg() {
    [[ -e $backup_password ]] || err "$backup_password does not exist"
    [[ -s $backup_password ]] || err "$backup_password must be non-empty file"
    mkdir -p -m 700 /tmp/gnupg
    gpg --homedir=/tmp/gnupg --passphrase-file="$backup_password" --batch -q "$@"
}

# -m specifies the mode for decrypted file, the encrypted file
# defaults to umask.
ensure_encrypt_decrypt() {
    local OPTIND opt check= encrypted decrypted body1 body2
    while getopts cm: opt; do
	case "$opt" in
	    c ) check="1";;
	    * ) getopts_err;;
	esac
    done
    shift $((OPTIND - 1))

    encrypted="$1" decrypted="$2"
    shift 2

    [[ $# -eq 0 ]] || err "too many arguments"

    if [[ ! -s $encrypted ]]; then
	if [[ ! -s $decrypted ]]; then
	    [[ $check ]] && return 1

	    # Create an empty file for convinience and report an error
	    [[ -e "$decrypted" ]] || touch "$decrypted"

	    err "Cannot ensure encrypted/decrypted file pair as both" \
		"$encrypted and $decrypted are empty or do not exist." \
		"Fill $decrypted with plain context and run again".
	fi

	log "encrypting $decrypted into $encrypted"
	tmp_files+=("$encrypted.tmp")
	run_gpg --cipher-algo AES256 --symmetric < "$decrypted" > "$encrypted.tmp" || \
	    err "Failed to encrypt $decrypted into $encrypted"
	mv -fT "$encrypted.tmp" "$encrypted"
    fi

    if [[ ! -s "$decrypted" ]]; then
	log "decrypting $encrypted into $decrypted"
	tmp_files+=("$decrypted.tmp")
	run_gpg -d < "$encrypted" > "$decrypted.tmp" || \
	    err "Failed to decrypt $encrypted into $decrypted"
	mv -fT "$decrypted.tmp" "$decrypted"
    fi

    body1=$(base64 -w0 "$decrypted")
    body2=$(run_gpg -d < $encrypted | base64 -w0)
    test "_$body1" = "_$body2" || \
	err "FAIL: $decrypted and its encrypted form $encrypted differ." \
	    "If $decrypted was updated with new content," \
	    "remove $encrypted and run again."
}

is_same_file_content() {
    local path1="$1" path2="$2"
    if cmp --silent "$path1" "$path2"; then
	return 0
    fi
    return 1
}

readonly VOLUME_LIST_SPAN=5

setup_volumes() {
    log "checking volumes"
    local i

    local -A volume_map=()
    for ((i=0; i<${#volume_list[@]}; i+=VOLUME_LIST_SPAN)); do
        local volume="${volume_list[i]}"
	[[ $volume =~ ^/vol/[^/] ]] || \
	    err "volume does not starts with /vol/ - $volume"
	[[ $volume =~ // ]] && \
	    err "volume contains sequences of slashes - $volume"
	[[ $volume =~ /$ ]] && \
	    err "volume ends with slash - $volume"
        [[ -z ${volume_map[$volume]-} ]] || err "duplicated volume $volume"
        volume_map[$volume]=1
    done

    local -a parent_list=()
    local -A parent_map=()
    for ((i=0; i<${#volume_list[@]}; i+=VOLUME_LIST_SPAN)); do
        local volume="${volume_list[i]}"

        local path="${volume#/vol/}" parent=/vol
        while :; do
            local dirname="${path%%/*}"
            [[ $dirname != $path ]] || break
	    parent+="/$dirname"
            [[ -z ${volume_map[$parent]-} ]] || \
                err "volume $volume is a sub-directory of $parent volume"
            if [[ -z ${parent_map[$parent]-} ]]; then
                parent_map[$parent]=1
                parent_list+=("$parent")
            fi
            path="${path#*/}"
        done
    done

    for ((i=0; i<${#parent_list[@]}; i+=1)); do
        ensure_dir "${parent_list[i]}" root:root 755
    done
    for ((i=0; i<${#volume_list[@]}; i+=VOLUME_LIST_SPAN)); do
        local volume="${volume_list[i]}"
        local user="${volume_list[i+1]}"
        local group="${volume_list[i+2]}"
        local dirmode="${volume_list[i+3]}"
        local filemode="${volume_list[i+4]}"
	if [[ ! $user ]]; then
	    user=root
	fi
	ensure_dir "$volume" "$user:$group" "$dirmode"
    done
}

setup_volume_tree() {
    local i
    for ((i=0; i<${#volume_list[@]}; i+=VOLUME_LIST_SPAN)); do
        local volume="${volume_list[i]}"
        local user="${volume_list[i+1]}"
        local group="${volume_list[i+2]}"
        local dirmode="${volume_list[i+3]}"
        local filemode="${volume_list[i+4]}"

        log "checking $volume subtree"

        # To minimize the number of find invocations for the common case
        # of no changes first run find to check if anything has unexpected
        # ownership or permissions.
        local top="$volume"
	local ownership_test=( \( -user "$user" -group "$group" \) )

        local -a find_test
        if [[ -z $filemode ]]; then
            find_test=(
                \(
                \( -type d -not -perm "$dirmode" \) -or
                 -not "${ownership_test[@]}"
                \)
            )
        else
            find_test=(
                \(
                \( -type d -not -perm "$dirmode" \) -or
                \( \( -type f -or -type p \) -not -perm "$filemode" \) -or
                -not "${ownership_test[@]}"
                \)
            )
        fi
        local s
        s="$(find "$top" -mindepth 1 "${find_test[@]}" -printf 1 -quit)"
        [[ $s ]] || continue

        local step
        for step in ownership dirmode filemode; do
            local blob
            local -a cmd=()
            case $step in
            ownership )
                find_test=( -not "${ownership_test[@]}" )
		if [[ $user ]]; then
		    cmd=( chown -h "$user:$group" )
		else
		    cmd=( chgrp -h "$group" )
		fi
                ;;
            dirmode )
                find_test=( -type d -not -perm "$dirmode" )
                cmd=( chmod "=$dirmode" )
                ;;
            filemode )
                [[ $filemode ]] || continue
                find_test=( \( -type f -or -type p \) -not -perm "$filemode" )
                cmd=( chmod "=$filemode" )
                ;;
            * ) err "$step" ;;
            esac
            blob="$(find "$top" -mindepth 1 "${find_test[@]}" -print0 | base64 -w0)"
            [[ $blob ]] || continue

            # Log only few entries
	    if [[ ${#blob} -le 400 ]]; then
		s="$(printf %s "$blob" | base64 -d | xargs -0 echo | tr -cd " -~" || :)"
	    else
		s="$(printf %s "$blob" | base64 -d | xargs -0 echo 2>/dev/null | head -q -c 300 | tr -cd " -~" || :)..."
	    fi
            printf "  %s %s\\n" "${cmd[*]}" "$s" 1>&2
            printf %s "$blob" | base64 -d | xargs -0 -r "${cmd[@]}"
        done
    done
}
