# hfi-reader

## Requirements

Linux kernel version >= 5.18, with `CONFIG_INTEL_HFI_THERMAL`.

12th/13th Gen Intel Core CPUs (Alder Lake, Raptor Lake)

## Build

```
sudo apt install libnl-genl-3-dev cmake
mkdir build && cd build
cmake ..
make
```

## Code

`hfi-events.c` is copied/modified from kernel source code https://github.com/torvalds/linux/tree/master/tools/power/x86/intel-speed-select
