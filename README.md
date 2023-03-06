# vcpuchecker

## Requirements

- 12th/13th Gen Intel Core CPUs (Alder Lake, Raptor Lake)
- (optional) Linux kernel version >= 5.18, with kernel config `CONFIG_INTEL_HFI_THERMAL` to show CPU HFI info from HW.

## Build

```
git submodule update --init --recursive
sudo apt install libelf-dev zlib1g-dev libnl-genl-3-dev libvirt-dev cmake
mkdir build && cd build
cmake ..
make
```

## HFI per-core data

When the tool starts the perf/effi values are set based on the most common values if no CPU load, in case:
1. Kernel is old or INTEL_HFI_THERMAL is not enabled
2. Some models report HFI data rarely, so after booting up the user space will not get a notification for a long time.

So common values are given manually at the tool starting, if HFI notification is properly set and the CPU models do report often, it could be changed anytime a HFI data notification is sent to user space.
