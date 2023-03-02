# vcpuchecker

## Requirements

- 12th/13th Gen Intel Core CPUs (Alder Lake, Raptor Lake)
- (optional) Linux kernel version >= 5.18, with kernel config `CONFIG_INTEL_HFI_THERMAL` to show CPU HFI info from HW.

## Build

```
sudo apt install libelf-dev zlib1g-dev libnl-genl-3-dev cmake
mkdir build && cd build
cmake ..
make
```
