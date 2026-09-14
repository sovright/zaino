#!/usr/bin/env bash
# Enumerate ext4 directory entries and inode metadata without executing image content.
set -euo pipefail
export LC_ALL=C
fail() { echo "ext4 inspection refused: $*" >&2; exit 1; }
[[ $# == 2 ]] || fail 'usage: inspect-ext4-tree.sh IMAGE OUTPUT'
image=$1 output=$2
[[ -f "$image" && ! -e "$output" ]] || fail 'invalid image or output'
command -v debugfs >/dev/null || fail 'missing debugfs'
scratch=$(mktemp -d); trap 'rm -rf -- "$scratch"' EXIT

run_debugfs() {
  local command=$1 result=$2 stderr="$scratch/stderr"
  debugfs -R "$command" "$image" >"$result" 2>"$stderr" || fail "debugfs command failed: $command"
  sed '/^debugfs [0-9]/d' "$stderr" >"$scratch/errors"
  [[ ! -s "$scratch/errors" ]] || fail "debugfs reported an error: $command"
}

mode_record() {
  local mode=$1 uid=$2 gid=$3 path=$4 type
  case ${mode:0:2} in
    04) type=d ;;
    10) type=f ;;
    *) fail "unsupported inode type at $path" ;;
  esac
  permissions=$((8#${mode: -4}))
  (( (permissions & 8#6000) == 0 )) || fail "set-id inode at $path"
  [[ "$type" != f ]] || (( (permissions & 8#0002) == 0 )) || fail "world-writable file at $path"
  printf '%s %04o %s %s %s\n' "$type" "$permissions" "$uid" "$gid" "$path" >>"$scratch/inventory"
}

run_debugfs 'stat /' "$scratch/root-stat"
root_mode=$(awk '/^Inode:/ {for(i=1;i<=NF;i++) if($i=="Mode:") {print $(i+1); exit}}' "$scratch/root-stat")
root_inode=$(awk '/^Inode:/ {print $2; exit}' "$scratch/root-stat")
root_uid=$(awk '/^User:/ {print $2; exit}' "$scratch/root-stat")
root_gid=$(awk '/^User:/ {print $4; exit}' "$scratch/root-stat")
[[ "$root_inode" =~ ^[0-9]+$ && "$root_mode" =~ ^0[0-7]{3}$ && "$root_uid" =~ ^[0-9]+$ && "$root_gid" =~ ^[0-9]+$ ]] || fail 'malformed root inode metadata'
mode_record "04$root_mode" "$root_uid" "$root_gid" .
run_debugfs 'ea_list /' "$scratch/root-ea"
[[ ! -s "$scratch/root-ea" ]] || fail 'extended inode metadata at root'

queue=(/); paths=(.)
declare -A seen_inodes=(["$root_inode"]=.)
for ((index=0; index<${#queue[@]}; index++)); do
  directory=${queue[index]}; relative=${paths[index]}; listing="$scratch/list-$index"
  run_debugfs "ls -p $directory" "$listing"
  while IFS=/ read -r empty inode mode uid gid name size trailing; do
    [[ -z "$empty$inode$mode$uid$gid$name$size$trailing" ]] && continue
    [[ -z "$empty" && -z "$trailing" ]] || fail "malformed directory listing: $directory"
    if [[ "$inode" == 0 && "$mode" == 000000 && "$uid" == 0 && "$gid" == 0 && -z "$name" && "$size" == 0 ]]; then continue; fi
    [[ "$inode" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]{6}$ && "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]] || fail "malformed inode metadata: $directory"
    [[ "$name" == . || "$name" == .. ]] && continue
    [[ "$name" =~ ^[A-Za-z0-9._+-]+$ && "$name" != *..* ]] || fail "unsafe image path component: $name"
    path=${relative#./}; [[ "$path" == . ]] && path=''; [[ -n "$path" ]] && path="$path/"
    path="./$path$name"
    [[ -z ${seen_inodes[$inode]+x} ]] || fail "aliased or cyclic inode at $path"
    seen_inodes[$inode]=$path
    (( ${#seen_inodes[@]} <= 256 )) || fail 'inode traversal limit exceeded'
    mode_record "$mode" "$uid" "$gid" "$path"
    run_debugfs "ea_list /${path#./}" "$scratch/ea"
    [[ ! -s "$scratch/ea" ]] || fail "extended inode metadata at $path"
    if [[ ${mode:0:2} == 04 ]]; then queue+=("/${path#./}"); paths+=("$path"); fi
  done <"$listing"
done
sort -u "$scratch/inventory" >"$output"
[[ $(wc -l <"$output") == $(wc -l <"$scratch/inventory") ]] || fail 'duplicate filesystem path'
