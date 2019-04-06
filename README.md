# EasyPak

A binary package tool. package a minimal filesystem to a single file.

## Usage

```bash
ezbin targetexecutable buildinstrustion
```

## buildinstrustion example

```
print Hello world
warn It will be output to stderr
mktmpfs /tmp
bind /proc:/tmp/proc
chroot /tmp
chdir /
@data
exec-passthru /usr/bin/endpoint
```

`@data` is means package all files in data directory to target executable

### PS

1. Only support normal files
2. Only perserve 9bit permission info, no owner uid/gid or SELinux context

## command list
 * print: print something to stdout
 * warn: print something to stderr
 * strategy:<br>
   `overwrite:0` means threat overwriting files as error<br>
   `overwrite:1` means force overwrite files<br>
   `overwrite:2` means skip exist files
 * chdir: just change current working directory<br>
   PS: will create target directory automatically
 * mkdir: create directory
 * mktmpfs: mount tmpfs to target directory<br>
   PS: will create target directory automatically
 * chroot: change root directory
 * pivot_root
 * bind: just like `mount --bind` command
 * exec: execute command
 * exec-passthru: execute command but passthrough all arguments to it