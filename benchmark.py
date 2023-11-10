B
    ��Ne{  �            	   @   s�  d dl Z d dlZd dlZd dlZd dlZd dlZd dlZd dlZe�d� d Z	i Z
dZdZed���Zx�ee�D ]�\Z	Zdekr�e�d�Zeeed � Zed e�d�d � ZeZeZee
kr�ed	d	dd
�ge
e< ne
e �ed	d	dd
�� qned e�d�d � ZxHe
e D ]<Zed ek�rdek�r4eed< ned  de 7  < �qW qnW W dQ R X e�d� edd��Ze�eje
dd�� W dQ R X g Zx2edd�D ]$Zdee� d	dd�Ze�e� �q�W edd��Ze�ejedd�� W dQ R X e�d� e�d� e� d��!� Z"de"k�r�e"de"�#d�� e"e"�#d�d d�  Z"e�d� e�d� ed d��Ze�e"� W dQ R X e�d!� e�d"� e�d#� dS )$�    Nz$lspci -nn | grep NVIDIA > outIP.temp� z
outIP.tempz:00.0z10de:�	   �   F)�pciId�usedZdisabled�vmz:00r   ZadditionalIds�,z)/home/tensordock/tensordock/dataGPUs.json�w�   )�indent�   ��   z192.168.122.)Zipr   r   z(/home/tensordock/tensordock/dataIPs.jsonz1sudo echo "#!/bin/bash" > /etc/libvirt/hooks/qemuz%sudo chmod +x /etc/libvirt/hooks/qemuzsudo virsh net-dumpxml defaultz<dhcp>z</dhcp>�   zsudo virsh net-destroy defaultzsudo virsh net-undefine defaultz'/home/tensordock/tensordock/network.xmlz=sudo virsh net-define /home/tensordock/tensordock/network.xmlzsudo virsh net-start defaultz sudo virsh net-autostart default)$�argparse�
subprocessZrandom�osZtime�base64�sysZjson�system�countZgpuDataZ	prevGpuIdZ	prevPciId�open�contents�	enumerate�line�rfindZ
gpuIdIndexZgpuIdr   �appendZgpu�removeZoutfile�write�dumpsZipAddresses�range�i�strZipAddressDict�popen�readZ
networkXml�find� r%   r%   �benchmark.py�<module>   sh   @




(




(



