import argparse, subprocess, random, os, time, base64, sys, json

# We already know that there is an extra VGA device aboard; so we can just take all NVIDIA devices
os.system('lspci -nn | grep NVIDIA > outIP.temp')
count = 0
gpuData = {}

# Loop through the new file, and add the GPU data to the dictionary
prevGpuId = ""
prevPciId = ""

with open("outIP.temp") as contents:
    for count, line in enumerate(contents):
        if(":00.0" in line):
            gpuIdIndex = line.rfind("10de:")
            gpuId = line[gpuIdIndex:gpuIdIndex+9]
            pciId = line[0:line.rfind(":00.0")+5]
            prevGpuId = gpuId
            prevPciId = pciId
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
        else:
            pciId = line[0:line.rfind(":00")+5]
            for gpu in gpuData[prevGpuId]:
                if(gpu["pciId"] == prevPciId):
                    if("additionalIds" not in gpu):
                        gpu["additionalIds"] = pciId
                    else:
                        gpu["additionalIds"] += "," + pciId
            # gpuData[prevGpuId].append({
            #     "pciId": pciId,
            #     "used": False,
            #     "disabled": False,
            #     "vm": None
            # })

os.remove('outIP.temp')

with open("/home/tensordock/tensordock/dataGPUs.json", "w") as outfile:
    outfile.write(json.dumps(gpuData, indent=1))


# Create a new file storing an array of IP addresses from range 192.168.122.2-192.168.122.253
ipAddresses = []
for i in range(2, 254):
    ipAddressDict = {
        "ip": "192.168.122." + str(i),
        "used": False,
        "vm": None
    }
    ipAddresses.append(ipAddressDict)

with open("/home/tensordock/tensordock/dataIPs.json", "w") as outfile:
    outfile.write(json.dumps(ipAddresses, indent=1))