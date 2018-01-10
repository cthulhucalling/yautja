#!/usr/bin/python

import splunk
import time
import json
import datetime

search="search index=carbon process_path=*powershell.exe* OR process_path=*cscript.exe* OR process_path=*wscript.exe* AND direction=outbound AND NOT (remote_ip=134.20.* OR remote_ip=141.221.* OR remote_ip=127.0.0.1) AND remote_ip=* earliest=-24h"

#this is for non-proxy aware script connections
sessionkey=splunk.login()
if sessionkey:
        print "We have a session key!"
        auth_header={'Authorization':'Splunk %s' %sessionkey}
        search_id=splunk.create_search(auth_header,search)
        print "The search ID is: "+search_id
        if search_id:
                #Check status of job
                status=splunk.check_status(auth_header,search_id)
                while (int(status)<>1):
                        #print "Job is not done"
                        time.sleep(5)
                        status=splunk.check_status(auth_header,search_id)

                print "Ding! Fries are done"
                results=splunk.get_results(auth_header,search_id)
                if results:
                        j=json.loads(results)
                        #print json.dumps(j,indent=4)
                        print "Script initiated network connections to non-INL addresses (not proxy aware). Last 24hours"
                        print "Local IP\tProcess Name\t\t\t\tRemote IP\tRemote Domain"
                        print "-----------------------------------------------------------------------------------"
                        for result in j["results"]:
                                a=json.loads(result["_raw"])
                                print "%s\t%s\t\t\t\t%s\t%s" %(a["local_ip"],a["process_path"],a["remote_ip"],a["domain"])

#Proxy-aware scripted connections
#This will require multiple lookups as we have to pivot on each connection and look up the Bluecoat logs
#Jed makes this harder as we won't add the client port to the Bluecoat logs and the clocks on all of the workstations are not synchronized

search="search index=carbon process_path=*powershell.exe* OR process_path=*cscript.exe* OR process_path=*wscript.exe* AND direction=outbound AND remote_ip=134.20.11.85 earliest=-24h"
search_id=splunk.create_search(auth_header,search)
print "The search ID is: "+search_id
if search_id:
        #Check status of job
        status=splunk.check_status(auth_header,search_id)
        while (int(status)<>1):
                #print "Job is not done"
                time.sleep(5)
                status=splunk.check_status(auth_header,search_id)
        print "Ding! Fries are done"
        results=splunk.get_results(auth_header,search_id)
        if results:
                print ""
                print "Potentially script-initiated proxy-aware connections"
                print "Local IP\tUsername\tDestination Domain\tDestination IP"
                print "--------------------------------------------------------"
                j=json.loads(results)
                #print json.dumps(j,indent=4)
                for result in j["results"]:
                        b=json.loads(result["_raw"])
                        earliest=datetime.datetime.fromtimestamp(float(b["timestamp"]))-datetime.timedelta(minutes=10)
                        latest=datetime.datetime.fromtimestamp(float(b["timestamp"]))+datetime.timedelta(minutes=10)
                        earliest=str(earliest.strftime("%m/%d/%Y:%H:%M:%S")).strip()
                        latest=str(latest.strftime("%m/%d/%Y:%H:%M:%S")).strip()
                        #print "%s %s %s %s" %(b["local_ip"],time,earliest,latest)
                        search="search index=cybersec sourcetype=Bluecoat:* c_ip="+b["local_ip"]+" earliest="+earliest+" latest="+latest
                        search_id=splunk.create_search(auth_header,search)
                        if search_id:
                                #Check status of job
                                status=splunk.check_status(auth_header,search_id)
                                while (int(status)<>1):
                                        #print "Job is not done"
                                        time.sleep(5)
                                        status=splunk.check_status(auth_header,search_id)
                                print "Ding! Fries are done"
                                results=splunk.get_results(auth_header,search_id)
                                if results:
                                        j=json.loads(results)
                                        #print json.dumps(j,indent=4)
                                        for result in j["results"]:
                                                a=result["_raw"].split()
                                                bad=["tcp","ssl","http"]
                                                if a[15] in bad:
                                                        id=16
                                                else:
                                                        id=15
                                                print "%s\t%s\t%s\t%s" %(a[3],a[4],a[id],a[id+1])



