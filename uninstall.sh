sudo apt-get purge libvirt* kvm qemu*
sudo apt autoremove


echo "We have to tell the host to ignore the "
echo "GPUs that will be passed through"
IDS=`lspci -nnk -d 10de: | grep NVIDIA | grep -v Subsystem | awk -F '10de:' {'print $2'} | awk -F ']' {'print "10de:"$1'} `
IDS=`echo $IDS | tr ' ' ','`

# Now, let us remove those IDs from the grub and disable IOMMU
sed -i "s/GRUB_CMDLINE_LINUX_DEFAULT=\"intel_iommu=on amd_iommu=on vfio_iommu_type1.allow_unsafe_interrupts=1 initcall_blacklist=sysfb_init vfio-pci.ids=${IDS}\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\"/" /etc/default/grub
rm /etc/modprobe.d/vfio.conf

sed -i 's/vfio-pci//' /etc/modules
sed -i 's/net.ipv4.ip_forward=1/#net.ipv4.ip_forward=1/' /etc/sysctl.conf

sed -i 's/options vfio_iommu_type1 allow_unsafe_interrupts=1//' /etc/modprobe.d/iommu_unsafe_interrupts.conf
sed -i 's/options kvm ignore_msrs=1//' /etc/modprobe.d/kvm.conf

sed -i 's/\(.*\)blacklist snd_hda_intel/\1/' /etc/modprobe.d/blacklist.conf
sed -i 's/\(.*\)blacklist amd76x_edac/\1/' /etc/modprobe.d/blacklist.conf
sed -i 's/\(.*\)blacklist vga16fb/\1/' /etc/modprobe.d/blacklist.conf
sed -i 's/\(.*\)blacklist rivafb/\1/' /etc/modprobe.d/blacklist.conf
sed -i 's/\(.*\)blacklist nouveau/\1/' /etc/modprobe.d/blacklist.conf
sed -i 's/\(.*\)blacklist rivatv/\1/' /etc/modprobe.d/blacklist.conf
sed -i 's/\(.*\)blacklist nvidiafb/\1/' /etc/modprobe.d/blacklist.conf