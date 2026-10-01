## Setup scripts for a ConnectX5 NIC that connects to OpenNIC shell

Since OpenNIC shell by default does not support link auto-negotiation and link training, we must
disable these features on any NIC that connects with OpenNIC shell and configure link speed
manually.

Before running the scripts, make sure MST_DEV and IFACE are set to the correct device. The scripts
require the Mellanox tools from doca-ofed.

`permanent-setup.bash` disables auto-negotiation. This setting is stored on the card and survives
reboots.

`link-setup.bash` Configures the link for 100G operation with RS-FEC and forces the link status to
up.It must be run after every reboot or NIC reset.
