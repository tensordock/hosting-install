# Now the fun part: we will grab the PCI device IDs
lspci | grep VGA | grep -v NVIDIA
if [ $? -ne 0 ]; then
	echo "This computer doesn't have a non-NVIDIA VGA"
	echo "It's not possible configure GPU passthrough"
	echo "exiting"
	exit 1
fi

# Upgrade everything first
sudo apt update && sudo apt upgrade -y

echo "Welcome to the TensorDock Marketplace host installer."
echo "This will take approximately 30 minutes."

echo "Now, we will blocklist NVIDIA drivers"
# Now, we will blacklist all unnecessary drivers
cat << EOF >> /etc/modprobe.d/blacklist.conf
blacklist snd_hda_intel
blacklist amd76x_edac
blacklist vga16fb
blacklist nouveau
blacklist rivafb
blacklist nvidiafb
blacklist rivatv
EOF

echo "We have to tell the host to ignore the "
echo "GPUs that will be passed through"
IDS=`lspci -nnk -d 10de: | grep NVIDIA | grep -v Subsystem | awk -F '10de:' {'print $2'} | awk -F ']' {'print "10de:"$1'} `
IDS=`echo $IDS | tr ' ' ','`

# Now, let us put those IDs into the grub and enable the IOMMU
sed -i "s/GRUB_CMDLINE_LINUX_DEFAULT=\"\"/GRUB_CMDLINE_LINUX_DEFAULT=\"intel_iommu=on amd_iommu=on vfio_iommu_type1.allow_unsafe_interrupts=1 initcall_blacklist=sysfb_init vfio-pci.ids=${IDS}\"/" /etc/default/grub

# Now, we will put those IDs into the vfio conf file
echo "options vfio-pci ids=${IDS} disable_vga=1 disable_idle_d3=1" > /etc/modprobe.d/vfio.conf

# Now, let's add the vfio-pci module to the kernel
cat <<EOF >> /etc/modules
vfio-pci
EOF

# Allow unsafe interrupts (just like in the grub file but again)
echo "options vfio_iommu_type1 allow_unsafe_interrupts=1" > /etc/modprobe.d/iommu_unsafe_interrupts.conf

# Ignore messages, just as specified in the grub
echo "options kvm ignore_msrs=1" > /etc/modprobe.d/kvm.conf

# Enable IP port forwarding
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
sysctl -p

sudo apt update
sudo apt install -y libvirt-daemon libvirt-daemon-system virt-manager qemu-utils qemu-kvm genisoimage virt-viewer libguestfs-tools libosinfo-bin tuned cloud-image-utils
sudo apt install -y cpu-checker

# Set up the workspace
mkdir /home/tensordock/tensordock
wget -q -O /home/tensordock/tensordock/speedtest-cli.py https://raw.githubusercontent.com/sivel/speedtest-cli/master/speedtest.py
chmod +x /home/tensordock/tensordock/speedtest-cli.py > /dev/null
sudo apt install -y python3-pip nvme-cli fail2ban -y iperf3
sudo python3 benchmark.py

# Enable passwordless sudo execution
cat >> /etc/sudoers << EOF
tensordock ALL=(ALL) NOPASSWD:ALL
EOF

# Update grub
update-grub
update-initramfs -u

# Import OS templates
sudo wget https://templates.tensordock.cloud/ubuntu2004.qcow2 -O /var/lib/libvirt/images/template_ubuntu2004.qcow2
sudo wget https://templates.tensordock.cloud/ubuntu2204.qcow2 -O /var/lib/libvirt/images/template_ubuntu2204.qcow2
sudo wget https://templates.tensordock.cloud/ubuntu2004-ml-tensorflow.qcow2 -O /var/lib/libvirt/images/template_ubuntu2004-ml-tensorflow.qcow2
sudo wget https://templates.tensordock.cloud/ubuntu2004-ml-rapids.qcow2 -O /var/lib/libvirt/images/template_ubuntu2004-ml-rapids.qcow2
sudo wget https://templates.tensordock.cloud/ubuntu2004-ml-pytorch.qcow2 -O /var/lib/libvirt/images/template_ubuntu2004-ml-pytorch.qcow2
sudo wget https://templates.tensordock.cloud/ubuntu2004-ml-everything.qcow2 -O /var/lib/libvirt/images/template_ubuntu2004-ml-everything.qcow2
sudo wget https://templates.tensordock.cloud/windows10.qcow2 -O /var/lib/libvirt/images/template_windows10.qcow2

# Set ACL permissions
sudo setfacl -R -b /var/lib/libvirt/images
sudo setfacl -R -m u:$USER:rwX /var/lib/libvirt/images
sudo setfacl -m d:u:$USER:rwx /var/lib/libvirt/images

sudo iptables -t nat -A LIBVIRT_PRT -s 192.168.122.0/24 -j MASQUERADE
sudo reboot
