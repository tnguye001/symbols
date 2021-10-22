#!/bin/bash - 
#===============================================================================
#
#          FILE: create_symbols.sh
# 
#         USAGE: ./create_symbols.sh
# 
#   DESCRIPTION: This script supports one of the following distros: CentOS 8.2 Ubuntu 18.04 Ubuntu 20.04 Ubuntu 21.04
# 
#       OPTIONS: Run script without options
#  REQUIREMENTS: Centos 8.2, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 21.04
#        AUTHOR: Ahmad Saleh, Nir Rosen 
#  ORGANIZATION: Nvidia
#       CREATED: 07/01/21 00:17:33
#      REVISION: 1.3
#===============================================================================


echo "extracting go-lang..." 
cat go.tar.gz.* | tar xzvf -  &>/dev/null
go=$(pwd)/go/bin/go

echo "extracting dwarf2json..." 
sudo tar -C . -xzf dwarf2json.tar.gz

cd dwarf2json
$go build

. /etc/os-release

case "$ID" in
        "ubuntu")
                echo "Recognized UbuntuOS - Starting...."
                ubuntu_vmlinux_file=/usr/lib/debug/boot/vmlinux-$(uname -r)
                ubuntu_system_map_file=/boot/System.map-$(uname -r)
                        if [ -f "$ubuntu_vmlinux_file" ] && [ -f "$ubuntu_system_map_file" ]; then
                                        echo "found current kernel $(uname -r) debug files..."
                                        echo "executing dwarf2json..."
                                        sudo ./dwarf2json linux --elf $ubuntu_vmlinux_file --system-map $ubuntu_system_map_file > ../symbols.json
                        else
                                        echo "identified ubuntu system, installing debug symbols..."
                                        echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com $(lsb_release -cs)-proposed main restricted universe multiverse" | \
                                        sudo tee -a /etc/apt/sources.list.d/ddebs.list &>/dev/null
                                        sudo apt -y install ubuntu-dbgsym-keyring &>/dev/null
                                        sudo apt-get update &>/dev/null
                                        echo "Installing debug symbols...." 
                                        sudo apt-get -y install linux-image-$(uname -r)-dbgsym &>/dev/null
                                        if [ -f "$ubuntu_vmlinux_file" ] && [ -f "$ubuntu_system_map_file" ]; then
                                                echo "Running dwarf2json..."
                                                sudo ./dwarf2json linux --elf $ubuntu_vmlinux_file --system-map $ubuntu_system_map_file > ../symbols.json
                                        else
                                                echo "vmlinux and system map file not found"
                        fi
                fi
                ;;


        "centos")
                echo "Recognized CentOS - Starting...."
                centos_vmlinux_file=/usr/lib/debug/lib/modules/$(uname -r)/vmlinux
                centos_system_map_file=/boot/System.map-$(uname -r)
                        if [ -f "$centos_vmlinux_file" ] && [ -f "$centos_system_map_file" ]; then
                                        echo "found current kernel $(uname -r) debug files..."
                                        echo "Running dwarf2json..."
                                        sudo ./dwarf2json linux --elf $centos_vmlinux_file --system-map $centos_system_map_file > ../symbols.json
                                else
                                        echo "identified Centos system, installing debug symbols..."
                                        sed -i 's/enabled=0/enabled=1/g' /etc/yum.repos.d/CentOS-Linux-Debuginfo.repo
                                        yum -y install kernel-debuginfo &>/dev/null
                                        if [ -f "$centos_vmlinux_file" ] && [ -f "$centos_system_map_file" ]; then
                                                echo "Running dwarf2json..."
                                                sudo ./dwarf2json linux --elf $centos_vmlinux_file --system-map $centos_system_map_file > ../symbols.json
                                        else
                                                echo "vmlinux and system map files not found"
                        fi
                fi
                ;;
esac

echo "cleaning and exit."
cd ..
rm go1.16.4.linux-amd64.tar.gz
sudo rm -rf ./go
sudo rm -rf dwarf2json
