import argparse, subprocess, random, os, time, base64, sys, json

# We already know that there is an extra VGA device aboard; so we can just take all NVIDIA devices
os.system('lspci -nn | grep NVIDIA > outIP.temp')
count = 0
gpuData = {}

# Loop through the new file, and add the GPU data to the dictionary
with open("outIP.temp") as contents:
    for line in contents:
        if(":00.0" in line):
            gpuIdIndex = line.rfind("10de:")
            gpuId = line[gpuIdIndex:gpuIdIndex+9]
            pciId = line[0:line.rfind(":00.0")+5]
            if(gpuId not in gpuData):
                gpuData[gpuId] = [
                    {
                        "pciId": pciId,
                        "used": False,
                        "disabled": False,
                        "vm": None
                    }
                ]
            else:
                gpuData[gpuId].append({
                    "pciId": pciId,
                    "used": False,
                    "disabled": False,
                    "vm": None
                })
os.remove('outIP.temp')

with open("/home/tensordock/tensordock/dataGPUs.json", "w") as outfile:
    outfile.write(json.dumps(gpuData, indent=1))
