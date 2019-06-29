#!/bin/sh

die() {
  local r=$?
  local s="$*"
  if [ $r -eq 0 ]; then
    r=1
  fi
  if [ "$*" -eq "" ]; then
    s="unknown error"
  fi
  echo "E: $s"
  exit $r
}

do_busybox_links() {
  echo "Installing busybox links.."
  /bin/busybox --install -s || die "failed to install busybox links"
}

do_ln() {
  if [ -e $2 ]; then
    echo "$2 exists, skipping link creation"
  else
    echo "Linking $1 -> $2"
    ln -sf "$1" "$2" || die "failed to link fd"
  fi
}

do_mkdir() {
  local i
  if [ $# -ge 1 ]; then
    for i in $*; do
      echo "Making $1/"
      if [ -e /bin/mkdir ]; then
        mkdir -p "$1" || die "failed to make directory $1"
      else
        /bin/busybox mkdir -p "$1" || die "failed to make directory $1"
      fi
      shift
    done
  fi
}

do_mknod() {
  if [ -e "$2" ]; then
    echo "$2 exists, skipping device creation"
  else
    echo "Making $3"
    mknod -m "$1" "$2" "$3" "$4" "$5" || die "failed to create $2"
  fi
}

do_umount() {
  local i
  if [ $# -ge 1 ]; then
    for i in $*; do
      echo "Unmounting $1/"
      umount -f "$1" || echo "failed to unmount $1"
      shift
    done
  fi
}

do_mount() {
  case $# in
    2)
      # auto-probe filesystem type
      echo "Mounting $2"
      mount "$1" "$2" || die "failed to mount $2"
      ;;
    3)
      echo "Mounting $3"
      mount -t "$1" "$2" "$3" || die "failed to mount $3"
      ;;
    *)
      die "illegal number of arguments $# to do_mount"
      ;;
   esac
}

do_init() {
 
  do_mkdir \
    /bin \
    /etc \
    /dev \
    /proc \
    /root \
    /sbin \
    /sys \
    /tmp \
    /usr/bin \
    /usr/sbin \
    /var

  do_busybox_links

  # these must exist statically in the root fs, otherwise no processes would be able to run
  do_mknod 600 /dev/console c 5 1
  do_mknod 666 /dev/null c 1 3

  do_mount proc none /proc
  do_mount sysfs none /sys

  do_ln /proc/mounts /etc/mtab

  do_mount devtmpfs none /dev

  do_mknod 600 /dev/console c 5 1
  do_mknod 666 /dev/null c 1 3
  do_mknod 666 /dev/zero c 1 5
  do_mknod 666 /dev/ptmx c 5 2
  do_mknod 666 /dev/tty c 5 0
  do_mknod 444 /dev/random c 1 8
  do_mknod 444 /dev/urandom c 1 9

  do_mknod 666 /dev/fb0 c 29 0
  
  #chown root:tty /dev/console /dev/ptmx /dev/tty || die "failed to chown /dev files"

  do_ln /proc/self/fd /dev/fd
  do_ln /proc/self/fd/0 /dev/stdin
  do_ln /proc/self/fd/1 /dev/stdout
  do_ln /proc/self/fd/2 /dev/stderr
  do_ln /proc/kcore /dev/core

  do_mkdir \
    /dev/pts \
    /dev/shm
  
  do_mount devpts none /dev/pts
  do_mount tmpfs none /dev/shm
}

ROOT=""
ROOTFSTYPE=""
INIT="/sbin/init"
CONSOLE="/dev/console"

parse_cmdline() {
  local i
  local j=0
  for i in $(cat /proc/cmdline); do
    echo "cmdline[ $j ]: $i"
    if [ "" = "z" ]; then
      echo -n ""
    elif [ "console=" = "${i:0:7}" ]; then
      CONSOLE="${i:7}"
      echo "CONSOLE: ${CONSOLE}"
    elif [ "root=" = "${i:0:5}" ]; then
      ROOT="${i:5}"
      if [ "${ROOT}" = "/dev/ram" ]; then
        ROOT=""
      else
        echo "ROOT: ${ROOT}"
      fi
    elif [ "rootfstype=" = "${i:0:11}" ]; then
      ROOTFSTYPE="${i:11}"
      echo "ROOTFSTYPE: ${ROOTFSTYPE}"
    elif [ "init=" = "${i:0:5}" ]; then
      INIT="${i:5}"
      echo "INIT: ${INIT}"
      continue
    else
      echo -n ""
    fi
    j=$((j+1))
  done
}

main() {
  echo "Initializing.."
  do_init
  ifconfig eth0 up 0.0.0.0
  udhcpc -i eth0 &
  dropbear -R -B -E
}

main
