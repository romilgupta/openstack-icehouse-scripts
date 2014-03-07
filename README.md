openstack-icehouse-scripts
==========================

Openstack Icehouse installation


Openstack Icehouse Installation scripts for Ubuntu 12.04 LTS

For Openstack Controller :

Operating System : Ubuntu12.04 LTS

NIC's:

Eth0 : Public Network

Eth1: Openstack Management Network

This script install following components of openstack and configure them:

Keystone

Glance

Neutron( neutron-server with ml2)

Nova( nova-api nova-cert nova-scheduler nova-conductor novnc nova-consoleauth nova-novncproxy)

Dashboard

For Openstack Compute Node:

Operating System : Ubuntu12.04 LTS

NIC's:

Eth0 : Public Network

Eth1: Openstack Management Network

Eth2: Openstack Data Network

This script install following components of openstack and configure them:

Nova( nova-compute)

Neutron ( ovs-agent)

For Openstack Network Node:

Operating System : Ubuntu12.04 LTS

NIC's:

Eth0 : Public Network

Eth1: Openstack Management Network

Eth2: Openstack Data Network

This script install following components of openstack and configure them:

Neutron (dhcp-agent, l3-agent, ovs-agent)
