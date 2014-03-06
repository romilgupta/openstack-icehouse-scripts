#! /usr/bin/python
import sys
import os
import time
import fcntl
import struct
import socket
import subprocess

# These are module names which are not installed by default.
# These modules will be loaded later after downloading
iniparse = None
psutil = None


def kill_process(process_name):
    for proc in psutil.process_iter():
        if proc.name == process_name:
            proc.kill()


def delete_file(file_path):
    if os.path.isfile(file_path):
        os.remove(file_path)
    else:
        print("Error: %s file not found" % file_path)

def write_to_file(file_path, content):
    open(file_path, "a").write(content)

def add_to_conf(conf_file, section, param, val):
    config = iniparse.ConfigParser()
    config.readfp(open(conf_file))
    if not config.has_section(section):
        config.add_section(section)
        val += '\n'
    config.set(section, param, val)
    with open(conf_file, 'w') as f:
        config.write(f)


def delete_from_conf(conf_file, section, param):
    config = iniparse.ConfigParser()
    config.readfp(open(conf_file))
    if param is None:
        config.remove_section(section)
    else:
        config.remove_option(section, param)
    with open(conf_file, 'w') as f:
        config.write(f)


def get_from_conf(conf_file, section, param):
    config = iniparse.ConfigParser()
    config.readfp(open(conf_file))
    if param is None:
        raise Exception("parameter missing")
    else:
        return config.get(section, param)

def print_format(string):
    print "+%s+" %("-" * len(string))
    print "|%s|" % string
    print "+%s+" %("-" * len(string))

def execute(command, display=False):
    print_format("Executing  :  %s " % command)
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if display:
        while True:
            nextline = process.stdout.readline()
            if nextline == '' and process.poll() != None:
                break
            sys.stdout.write(nextline)
            sys.stdout.flush()

        output, stderr = process.communicate()
        exitCode = process.returncode
    else:
        output, stderr = process.communicate()
        exitCode = process.returncode

    if (exitCode == 0):
        return output.strip()
    else:
        print "Error", stderr
        print "Failed to execute command %s" % command
        print exitCode, output
        raise Exception(output)



def initialize_system():
    if not os.geteuid() == 0:
        sys.exit('Please re-run the script with root user')

    execute("apt-get clean" , True)
    execute("apt-get autoclean -y" , True)
    execute("apt-get update -y" , True)
    execute("apt-get install ubuntu-cloud-keyring python-setuptools python-iniparse python-psutil -y", True)
    delete_file("/etc/apt/sources.list.d/icehouse.list")
    execute("echo deb http://ubuntu-cloud.archive.canonical.com/ubuntu precise-updates/icehouse main >> /etc/apt/sources.list.d/icehouse.list")
    execute("apt-get update -y", True)
    execute("apt-get install vlan bridge-utils -y", True)
    execute("sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf")

    global iniparse
    if iniparse is None:
        iniparse = __import__('iniparse')

    global psutil
    if psutil is None:
        psutil = __import__('psutil')
#=================================================================================
#==================   Components Installation Starts Here ========================
#=================================================================================

ip_address = raw_input('Controller IP: ')
ip_address_mgnt= raw_input('Controller Mgmt IP: ')

def install_and_configure_ntp():
    execute("apt-get install ntp -y")
    execute("sed -i 's/server 0.ubuntu.pool.ntp.org/#server 0.ubuntu.pool.ntp.org/g' /etc/ntp.conf")
    execute("sed -i 's/server 1.ubuntu.pool.ntp.org/#server 1.ubuntu.pool.ntp.org/g' /etc/ntp.conf")
    execute("sed -i 's/server 2.ubuntu.pool.ntp.org/#server 2.ubuntu.pool.ntp.org/g' /etc/ntp.conf")
    execute("sed -i 's/server 3.ubuntu.pool.ntp.org/#server 3.ubuntu.pool.ntp.org/g' /etc/ntp.conf")
    execute("sed -i 's/server ntp.ubuntu.com/server %s/g' /etc/ntp.conf" %ip_address)
    execute("service ntp restart", True)	


def install_and_configure_neutron():
    neutron_conf = "/etc/neutron/neutron.conf"
    neutron_paste_conf = "/etc/neutron/api-paste.ini"
    neutron_plugin_conf = "/etc/neutron/plugins/ml2/ml2_conf.ini"
    neutron_dhcp_ini="/etc/neutron/dhcp_agent.ini"
    neutron_l3_ini="/etc/neutron/l3_agent.ini"
    execute("apt-get install openvswitch-switch openvswitch-datapath-dkms -y", True)
	
    execute("ovs-vsctl --may-exist add-br br-int")
    execute("ovs-vsctl --may-exist add-br br-eth2") 
    execute("ovs-vsctl --may-exist add-port br-eth2 eth2")
    execute("ovs-vsctl --may-exist add-br br-ex")
    execute("apt-get install neutron-plugin-openvswitch-agent neutron-dhcp-agent neutron-l3-agent neutron-metadata-agent -y", True)

    add_to_conf(neutron_conf, "DEFAULT", "core_plugin", "neutron.plugins.openvswitch.ovs_neutron_plugin.OVSNeutronPluginV2")
    add_to_conf(neutron_conf, "DEFAULT", "verbose", "True")
    add_to_conf(neutron_conf, "DEFAULT", "debug", "True")
    add_to_conf(neutron_conf, "DEFAULT", "auth_strategy", "keystone")
    add_to_conf(neutron_conf, "DEFAULT", "rabbit_host", ip_address_mgnt)
    add_to_conf(neutron_conf, "DEFAULT", "rabbit_port", "5672")
    add_to_conf(neutron_conf, "DEFAULT", "allow_overlapping_ips", "False")
    add_to_conf(neutron_conf, "DEFAULT", "root_helper", "sudo neutron-rootwrap /etc/neutron/rootwrap.conf")

    add_to_conf(neutron_paste_conf, "filter:authtoken", "auth_host", ip_address_mgnt)
    add_to_conf(neutron_paste_conf, "filter:authtoken", "auth_port", "35357")
    add_to_conf(neutron_paste_conf, "filter:authtoken", "auth_protocol", "http")
    add_to_conf(neutron_paste_conf, "filter:authtoken", "admin_tenant_name", "service")
    add_to_conf(neutron_paste_conf, "filter:authtoken", "admin_user", "neutron")
    add_to_conf(neutron_paste_conf, "filter:authtoken", "admin_password", "neutron")

    add_to_conf(neutron_plugin_conf, "DATABASE", "sql_connection", "mysql://neutron:neutron@%s/neutron"%ip_address_mgnt)
    add_to_conf(neutron_plugin_conf, "OVS", "bridge_mappings", "physnet1:br-eth2")
    add_to_conf(neutron_plugin_conf, "OVS", "tenant_network_type", "vlan")
    add_to_conf(neutron_plugin_conf, "OVS", "network_vlan_ranges", "physnet1:1000:2999")
    add_to_conf(neutron_plugin_conf, "OVS", "integration_bridge", "br-int")
    add_to_conf(neutron_plugin_conf, "securitygroup", "firewall_driver", "neutron.agent.linux.iptables_firewall.OVSHybridIptablesFirewallDriver")
    
    add_to_conf(neutron_dhcp_ini, "DEFAULT", "interface_driver", "neutron.agent.linux.interface.OVSInterfaceDriver")
    add_to_conf(neutron_dhcp_ini, "DEFAULT", "dhcp_driver", "neutron.agent.linux.dhcp.Dnsmasq")

    add_to_conf(neutron_l3_ini, "DEFAULT", "interface_driver", "neutron.agent.linux.interface.OVSInterfaceDriver")
	
    execute("service neutron-plugin-openvswitch-agent restart", True)
    execute("service neutron-dhcp-agent restart", True)
    execute("service neutron-l3-agent restart", True)
   

initialize_system()
install_and_configure_ntp()
install_and_configure_neutron()



