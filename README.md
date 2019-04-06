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

- `print message`: print something to stdout
- `warn message`: print something to stderr
- `strategy content`:<br>
  `overwrite:0` means threat overwriting files as error<br>
  `overwrite:1` means force overwrite files<br>
  `overwrite:2` means skip exist files
- `chdir target`: just change current working directory<br>
  PS: will create target directory automatically
- `mkdir target`: create directory
- `mktmpfs target`: mount tmpfs to target directory<br>
  PS: will create target directory automatically
- `chroot target`: change root directory
- `pivot_root src:target`
- `bind src:target`: just like `mount --bind` command
- `exec cmdline`: execute command
- `exec-passthru executable`: execute command but passthrough all arguments to it
- `fuse target`: use fuse to target directory
