o
    8�Ne{  �                	   @   s�  d dl Z d dlZd dlZd dlZd dlZd dlZd dlZd dlZe�d� d Z	i Z
dZdZed��xZee�D ]k\Z	Zdev rve�d�Zeeed � Zed e�d�d � ZeZeZee
vried	d	dd
�ge
e< q6e
e �ed	d	dd
�� q6ed e�d�d � Ze
e D ]Zed ekr�devr�eed< q�ed  de 7  < q�q6W d  � n1 s�w   Y  e�d� edd��Ze�eje
dd�� W d  � n1 s�w   Y  g Zedd�D ]Zdee� d	dd�Ze�e� q�edd��Ze�ejedd�� W d  � n	1 �s	w   Y  e�d� e�d� e� d��!� Z"de"v �rne"de"�#d�� e"e"�#d�d d�  Z"e�d� e�d� ed d��Ze�e"� W d  � n	1 �sXw   Y  e�d!� e�d"� e�d#� dS dS )$�    Nz$lspci -nn | grep NVIDIA > outIP.temp� z
outIP.tempz:00.0z10de:�	   �   F)�pciId�used�disabled�vmz:00r   �additionalIds�,z)/home/tensordock/tensordock/dataGPUs.json�w�   )�indent�   ��   z192.168.122.)�ipr   r   z(/home/tensordock/tensordock/dataIPs.jsonz1sudo echo "#!/bin/bash" > /etc/libvirt/hooks/qemuz%sudo chmod +x /etc/libvirt/hooks/qemuzsudo virsh net-dumpxml defaultz<dhcp>z</dhcp>�   zsudo virsh net-destroy defaultzsudo virsh net-undefine defaultz'/home/tensordock/tensordock/network.xmlz=sudo virsh net-define /home/tensordock/tensordock/network.xmlzsudo virsh net-start defaultz sudo virsh net-autostart default)$�argparse�
subprocess�random�os�time�base64�sys�json�system�count�gpuData�	prevGpuId�	prevPciId�open�contents�	enumerate�line�rfind�
gpuIdIndex�gpuIdr   �append�gpu�remove�outfile�write�dumps�ipAddresses�range�i�str�ipAddressDict�popen�read�
networkXml�find� r5   r5   �benchmark.py�<module>   s�   @ 


�
�	
�
����
'�
��


(

�

�