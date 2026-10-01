SCION-IP Translation in OpenNIC Shell with Vitis P4
===================================================

This repository contains the P4 code and Vivado design files for an instance of [Open NIC shell](1)
that offloads SCION-IP translation and checksum calculation from [Scitra-TUN](4).

This repository includes code from:
* [AMD OpenNIC Shell](1) (License: Apache-2.0)
* [AMD OpenNIC Driver](2) (License: GPL-2.0)
* Barefoot Networks (License: Apache-2.0)
* [SCION-CPP](3) (License: MIT)

Dependencies for building;
* Vivado 2023.1
* Vitis Networking P4 (SDNet P4)
* Ultrascale+ CMAC license (free)
* `hcam_base` and `hcam_advanced` licenses

Evaluation licenses for the AMD/Xilinx IP cores are sufficient.

Dependencies of the behavioral tests:
* [SCION Layers for Scapy](5) (License: GPL-2.0) (included as submodule)
  * [Scapy](6) (License: GPL-2.0)

Required Ubuntu packages:
* python3.12 -- install from deadsnakes PPA on Ubuntu 22.04
* python3.12-venv
* m4 -- macro processing language

Tested on Ubuntu 22.04, may work on Ubuntu 24.04, but the drivers do not build on Ubuntu 26.04.

[1]: https://github.com/Xilinx/open-nic-shell
[2]: https://github.com/Xilinx/open-nic-driver
[3]: https://github.com/lschulz/scion-cpp/
[4]: https://github.com/lschulz/scion-cpp/tree/main/scitra
[5]: https://github.com/lschulz/scapy-scion-int
[6]: https://github.com/secdev/scapy

### Repo Structure ###

* `open-nic-driver` Modified OpenNIC driver that advertises checksum offload capability to the kernel
* `p4` P4 code and behavioral model tests
* `python` Supporting Python modules
* `scripts` Helper scripts for hardware testing

### Behavioral P4 Tests with BMv2 for Vitis ###

The simulation tests use Python and Scapy. It's recommended to install everything in a virtual
environment.
```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -e ./python/scapy-scion-int[extras] # make sure the submodule has been cloned
pip install psutil
```

The Xilinx P4 compiler and behavioral model are closed-source and require a license check.

Make sure the Vitis environment is sourced by running (change path if Vitis is installed somewhere
else) and the `python` directory is in PYTHONPATH.
```bash
source /opt/Xilinx/Vitis/2023.1/settings64.sh
export PYTHONPATH=$(pwd)/python
```

Build the P4 amalgamation files, and compile for the behavioral model:
```bash
make -C p4
```

Run the behavioral model tests with `make -C p4 sim`.

### Building the Kernel Module (Driver) for OpenNIC Shell###

Follow the instructions in [open-nic-driver/README.md](./open-nic-driver/README.md).
