#!/bin/python

import os
import pprint
import xml.dom.minidom
import json
import sys


#stig_doc = xml.dom.minidom.parse("U_Red_Hat_Enterprise_Linux_7_STIG_V1R0-2_Manual-xccdf.xml")

stig_doc = xml.dom.minidom.parse(sys.argv[1])

mapping = {}

for node in stig_doc.getElementsByTagName("Group"):

    vuln_id = node.getAttribute("id")
    group_id = node.getElementsByTagName("title")[0].firstChild.data
    description = node.getElementsByTagName("title")[1].firstChild.data
    rules = node.getElementsByTagName("Rule")


    for node2 in rules:
        severity = node2.getAttribute("severity")

        sub_maps = {
            'GROUP' : group_id ,
            'SEVERITY' : severity,
            'DESCRIPTION' : description,
            #'DETAILS' : details
        }

    mapping[vuln_id] = sub_maps

with open("stig.json","w") as f:
    json.dump(mapping,f)

print(mapping)
