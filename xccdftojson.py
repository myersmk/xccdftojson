#!/usr/bin/python

import os
import xml.dom.minidom
import json
import sys
import pprint


#stig_doc = xml.dom.minidom.parse("U_Red_Hat_Enterprise_Linux_7_STIG_V1R0-2_Manual-xccdf.xml")

stig_doc = xml.dom.minidom.parse(sys.argv[1])

mapping = {}

for node in stig_doc.getElementsByTagName("Group"):
    title1 = node.getAttribute("title")
    vuln_id = node.getAttribute("id")
    group_id = node.getElementsByTagName("title")[0].firstChild.data
    description1 = node.getElementsByTagName("description")[1].firstChild.data

    for node2 in node.getElementsByTagName("Rule"):
        rule_id = node2.getAttribute("id")
        severity = node2.getAttribute("severity")
        weight = node2.getAttribute("weight")
        version = node2.getElementsByTagName("version")[0].firstChild.data
        title2 = node2.getElementsByTagName("title")[0].firstChild.data
        description2 = node2.getElementsByTagName("description")[0].firstChild.data
        # ident is a URL http://iase.disa.mil/cci and returns a 404
        #ident = node2.getAttribute("system")
        cci = node2.getElementsByTagName("ident")[0].firstChild.data
        fixtext = node2.getElementsByTagName("fixtext")[0].firstChild.data

        if severity == "high":
          cat = "CAT-I"
        elif severity == "medium":
          cat = "CAT-II"
        elif severity == "low":
          cat = "CAT-III"
        else:
          cat = "UNKNOWN"

    for fixes in node2.getElementsByTagName("fixtext"):
      fixref = fixes.getAttribute("fixref")
          
    for fix_ids in node2.getElementsByTagName("fix"):
      fix_id = fix_ids.getAttribute("id")
  
    for checks in node2.getElementsByTagName("check"):
      check = checks.getAttribute("system")
      check_content = checks.getElementsByTagName("check-content")[0].firstChild.data

    sub_maps = [
      {
            'GROUP' : group_id ,
            'TITLE': title1,
            'DESCRIPTION': description1,
            'ID': rule_id,
            'SEVERITY' : severity,
            'CAT': cat,
            'WEIGHT': weight,
            'VERSION': version,
            'TITLE': title2,
            'DESCRIPTION': description2,
            #'IDENT': ident,
            'CCI': cci,
            'FIXREF': fixref,
            'FIXTEXT': fixtext,
            'FIX_ID': fix_id,
            'FIX_CHECK': check,
            'CHECK_CONTENT': check_content
      },
        ]

    mapping[vuln_id] = sub_maps


with open(sys.argv[1].replace('xml', 'json'),"w") as f:
    json.dump(mapping,f)

pprint.pprint(mapping)
