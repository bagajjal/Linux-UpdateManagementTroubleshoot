#!/usr/bin/python

import sys
import os
import os.path
import socket
import datetime
import imp
import codecs
import json
import string
import platform
import re

from os import walk

rule_info_list = []
tmp_rule_info_list = []
output = []

return_json_output = False
oms_admin_conf_path = "/etc/opt/microsoft/omsagent/conf/omsadmin.conf"
oms_agent_dir = "/var/opt/microsoft/omsagent"
oms_agent_log = "/var/opt/microsoft/omsagent/log/omsagent.log"
current_mof = "/etc/opt/omi/conf/omsconfig/configuration/Current.mof"

class RuleInfo:
    def __init__(self, rule_id, rule_name, rule_description, status, log_msg, rule_group_id, rule_group_name, result_msg_id):
        self.RuleId = rule_id
        self.RuleName = rule_name
        self.RuleDescription = rule_description
        self.RuleGroupId = rule_group_id
        self.RuleGroupName = rule_group_name
        self.CheckResult = status
        self.CheckResultMessage = log_msg
        self.CheckResultMessageId = result_msg_id
        self.CheckResultMessageArguments = list()

class LogLevel:
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    INFO = "INFO"
    DEBUG = "DEBUG"

def write_log_output(rule_id, log_level, log_msg, *result_msg_args):
    global output
    global rule_info_list

    if(type(log_msg) != str): log_msg = str(log_msg)

    if log_level == LogLevel.DEBUG:
        log_msg = log_msg.replace("\n\t", "\n")
        log_msg = log_msg.replace("\n", "\n\t")
    else:
        # skip debug message for JSON output
        for rule_info in tmp_rule_info_list:
            if rule_info.RuleId == rule_id:
                rule_info.RuleId = "Linux-" + rule_info.RuleId
                rule_info.CheckResultMessage = log_msg

                if log_level == LogLevel.SUCCESS:
                    rule_info.CheckResult = "Passed"
                elif log_level == LogLevel.FAILED:
                    rule_info.CheckResult = "Failed"
                elif log_level == LogLevel.INFO:
                    rule_info.CheckResult = "Information"

                rule_info.CheckResultMessageId = rule_info.RuleId + "." + rule_info.CheckResult
                for arg in result_msg_args:
                    rule_info.CheckResultMessageArguments.append(arg)
            
                # Finally add to output list
                rule_info_list.append(rule_info)
                break

    output.append(log_level + ": " + log_msg + "\n")

def tmp_init_rule_info_list():
    # CheckResult, CheckResultMessage, CheckResultMessageId, CheckResultMessageArguments will be filled later
 
    # Check the OS Version
    tmp_rule_info_list.append(RuleInfo("OSCheck", "Operating System", "supported OS versions (https://docs.microsoft.com/en-us/azure/automation/automation-update-management#clients)", \
                                       "", "", "prerequisites", "Prerequisite Checks", ""))

    # Check for multiple workspaces
    tmp_rule_info_list.append(RuleInfo("MultiWorkspaceCheck", "Multi-homing", "OMS must be configured with only one workspace", \
                                       "", "", "servicehealth", "VM Service Health Check", ""))

    # Check if OMSAgent is installed
    tmp_rule_info_list.append(RuleInfo("OMSAgentInstallCheck", "OMS Agent", "OMS Agent must be installed on the machine", \
                                       "", "", "servicehealth", "VM Service Health Check", ""))

    # Check if OMSAgent is running
    tmp_rule_info_list.append(RuleInfo("OMSAgentStatusCheck", "OMS Agent status", "OMS Agent must be running on the machine", \
                                       "", "", "servicehealth", "VM Service Health Check", ""))

    # Check if hybrid worker package is present
    tmp_rule_info_list.append(RuleInfo("HybridWorkerPackgeCheck", "Hybrid worker", "Hybrid worker package must be present on the machine", \
                                       "", "", "servicehealth", "VM Service Health Check", ""))

    # Check if hybrid worker is running
    tmp_rule_info_list.append(RuleInfo("HybridWorkerStatusCheck", "Hybrid worker status", "Hybrid worker must be running on the machine", \
                                       "", "", "servicehealth", "VM Service Health Check", ""))

    # Check the general internet connectivity
    tmp_rule_info_list.append(RuleInfo("InternetConnectionCheck", "General Internet connectivity", "Machine must be connected to internet", \
                                       "", "", "connectivity", "Connectivity Check", ""))

    # Check the AgentService connectivity
    tmp_rule_info_list.append(RuleInfo("AgentServiceCheck", "Registration endpoint", "Proxy and firewall configuration must allow Automation Hybrid Worker agent to communicate with registration endpoint", \
                                       "",  "", "connectivity", "Connectivity Check", ""))
    # Check the JRDS connectivity
    tmp_rule_info_list.append(RuleInfo("JRDSConnectionCheck", "Operations endpoint", "Proxy and firewall configuration must allow Automation Hybrid Worker agent to communicate with operations endpoint", \
                                       "", "", "connectivity", "Connectivity Check", ""))

    # Check the ODS connectivity
    tmp_rule_info_list.append(RuleInfo("ODSConnectionCheck1", "ODS endpoint1", "Proxy and firewall configuration must allow Automation Hybrid Worker agent to communicate with ODS endpoint", \
                                       "", "", "connectivity", "Connectivity Check", ""))

    # Check the ODS connectivity
    tmp_rule_info_list.append(RuleInfo("ODSConnectionCheck2", "ODS endpoint2", "Proxy and firewall configuration must allow Automation Hybrid Worker agent to communicate with ODS endpoint", \
                                       "", "", "connectivity", "Connectivity Check", ""))

    # Check the ODS connectivity
    tmp_rule_info_list.append(RuleInfo("ODSConnectionCheck3", "ODS endpoint3", "Proxy and firewall configuration must allow Automation Hybrid Worker agent to communicate with ODS endpoint", \
                                       "", "", "connectivity", "Connectivity Check", ""))

    # Check the ODS connectivity
    tmp_rule_info_list.append(RuleInfo("ODSConnectionCheck4", "ODS endpoint4", "Proxy and firewall configuration must allow Automation Hybrid Worker agent to communicate with ODS endpoint", \
                                       "", "", "connectivity", "Connectivity Check", ""))

def check_os():
    os_version = platform.platform()
    supported_os_url = "https://docs.microsoft.com/en-us/azure/automation/automation-update-management#clients"
    # We support (Ubuntu 14.04, Ubuntu 16.04, SuSE 11, SuSE 12, Redhat 6, Redhat 7, CentOs 6, CentOs 7)
    if re.search("Ubuntu-14.04", os_version, re.IGNORECASE) or \
       re.search("Ubuntu-16.04", os_version, re.IGNORECASE) or \
       re.search("SuSE-11", os_version, re.IGNORECASE) or \
       re.search("SuSE-12", os_version, re.IGNORECASE) or \
       re.search("redhat-6", os_version, re.IGNORECASE) or \
       re.search("redhat-7", os_version, re.IGNORECASE) or \
       re.search("centos-6", os_version, re.IGNORECASE) or \
       re.search("centos-7", os_version, re.IGNORECASE) :
        write_log_output("OSCheck", LogLevel.SUCCESS, "Operating System version is supported")
    else:
        write_log_output("OSCheck", LogLevel.DEBUG, os_version)
        write_log_output("OSCheck", LogLevel.SUCCESS, "Operating System version is not supported. Supported versions listed here: " + supported_os_url, supported_os_url)

def check_endpoint(workspace, endpoint):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_endpoint = None
    
    if "*" in endpoint and workspace is not None:
        new_endpoint = endpoint.replace("*", workspace)
    elif "*" not in endpoint:
        new_endpoint = endpoint

    if new_endpoint is not None:
        try:
            response = sock.connect_ex((new_endpoint, 443))

            if response == 0:
                return True
            else:
                return False

        except Exception as ex:
            return False
    else:
        return False

def check_network_endpoints():
    workspace = get_workspace()

    # General intenet connection
    if check_endpoint(workspace, "bing.com") and check_endpoint(workspace, "google.com"):
        write_log_output("InternetConnectionCheck", LogLevel.SUCCESS, "Machine is connected to internet")
    else:
        write_log_output("InternetConnectionCheck", LogLevel.FAILED, "Machine is not connected to internet")

    # Agent service
    agent_endpoint = get_agent_endpoint()
    if  agent_endpoint is not None and check_endpoint(workspace, agent_endpoint):
        write_log_output("AgentServiceCheck", LogLevel.SUCCESS, "TCP test for {" + agent_endpoint + "} (port 443) succeeded", agent_endpoint)
    else:
        write_log_output("AgentServiceCheck", LogLevel.FAILED, "TCP test for {" + agent_endpoint + "} (port 443) failed", agent_endpoint)

    # JRDS service
    jrds_endpoint = get_jrds_endpoint(workspace)
    if jrds_endpoint is not None and check_endpoint(workspace, jrds_endpoint):
        write_log_output("JRDSConnectionCheck", LogLevel.SUCCESS, "TCP test for {" + jrds_endpoint + "} (port 443) succeeded", jrds_endpoint)
    else:
        write_log_output("JRDSConnectionCheck", LogLevel.FAILED, "TCP test for {" + jrds_endpoint + "} (port 443) succeeded", jrds_endpoint)

    ods_endpoints = ["*.ods.opinsights.azure.com", "*.oms.opinsights.azure.com", "ods.systemcenteradvisor.com"]

    fairfax_endpoints = ["usge-jobruntimedata-prod-1.usgovtrafficmanager.net", "usge-agentservice-prod-1.usgovtrafficmanager.net", 
                    "*.ods.opinsights.azure.us", "*.oms.opinsights.azure.us" ]

    i = 0
    if is_fairfax_region() is True:
        for endpoint in fairfax_endpoints:
            i += 1
            if "*" in endpoint and workspace is not None:
                endpoint = endpoint.replace("*", workspace)

            if check_endpoint(workspace, endpoint):
                write_log_output("ODSConnectionCheck" + str(i), LogLevel.SUCCESS, "TCP test for {" + endpoint + "} (port 443) succeeded", endpoint)
            else:
                write_log_output("ODSConnectionCheck" + str(i), LogLevel.FAILED, "TCP test for {" + endpoint + "} (port 443) failed", endpoint)
    else:
        for endpoint in ods_endpoints:
            i += 1
            if "*" in endpoint and workspace is not None:
                endpoint = endpoint.replace("*", workspace)

            if check_endpoint(workspace, endpoint):
                write_log_output("ODSConnectionCheck" + str(i), LogLevel.SUCCESS, "TCP test for {" + endpoint + "} (port 443) succeeded", endpoint)
            else:
                write_log_output("ODSConnectionCheck" + str(i), LogLevel.FAILED, "TCP test for {" + endpoint + "} (port 443) failed", endpoint)

def get_jrds_endpoint(workspace):
    if workspace is not None:
        worker_conf_path = "/var/opt/microsoft/omsagent/" + workspace + "/state/automationworker/worker.conf"
        line = find_line_in_path("jrds_base_uri", worker_conf_path)
        if line is not None:
            return line.split("=")[1].split("/")[2].strip()

    return None

def get_agent_endpoint():
    line = find_line_in_path("agentservice", oms_admin_conf_path)
    if line is not None:
        return line.split("=")[1].split("/")[2].strip()

    return None

def check_oms_agent_installed():
    if os.path.isfile(oms_admin_conf_path):
        write_log_output("OMSAgentInstallCheck", LogLevel.SUCCESS, "OMS Agent is installed")
        oms_admin_file_content = "\t"
        oms_admin_file = open(oms_admin_conf_path, "r")
        for line in oms_admin_file:
            oms_admin_file_content += line

        write_log_output("OMSAgentInstallCheck", LogLevel.DEBUG, "OMS Admin conf contents:\n" + oms_admin_file_content)
    else:
        write_log_output("OMSAgentInstallCheck", LogLevel.FAILED, "OMS Agent is not installed. Couldn't find omsadmin.conf (" + oms_admin_conf_path + ")")
        return

    if os.path.isfile(oms_agent_log):
        write_log_output("OMSAgentInstallCheck", LogLevel.SUCCESS, "OMS Agent is installed")
    else:
        write_log_output("OMSAgentInstallCheck", LogLevel.FAILED, "OMS Agent is not installed. Couldn't find " + oms_agent_log)
        return
    
    # Check for multihoming of workspaces
    directories = []
    potential_workspaces = []

    for (dirpath, dirnames, filenames) in walk(oms_agent_dir):
        directories.extend(dirnames)
        break # Get the top level of directories

    for directory in directories:
        if len(directory) >= 32:
            potential_workspaces.append(directory)

    if len(potential_workspaces) > 1:
        write_log_output("MultiWorkspaceCheck", LogLevel.INFO, "OMS Agent is multihomed. List of workspaces: " + str(potential_workspaces))

def check_hybrid_worker_running():
    if os.path.isfile(current_mof) == False:
        write_log_output("HybridWorkerStatusCheck", LogLevel.FAILED, "Hybrid worker is not running")
        write_log_output("HybridWorkerStatusCheck", LogLevel.DEBUG, "current_mof file:(" + current_mof + ") is missing")
        return

    search_text = "ResourceSettings"
    command = "file -b --mime-encoding " + current_mof
    current_mof_encoding = os.popen(command).read()

    tmp = find_line_in_path("ResourceSettings", current_mof, current_mof_encoding);
    if tmp is None:
        write_log_output("HybridWorkerStatusCheck", LogLevel.FAILED, "Hybrid worker is not running")
        write_log_output("HybridWorkerStatusCheck", LogLevel.DEBUG, "Unable to fetch ResourceSettings from current_mof file:(" + current_mof + ") with file encoding:" + current_mof_encoding)
        return

    tmp = string.replace(tmp, "\\", "")
    tmp = string.replace(tmp, ";", "")
    tmp = string.replace(tmp, "\"[", "[")
    tmp = string.replace(tmp, "]\"", "]")
    resourceSetting = tmp.split("=")[1].strip()

    automation_worker_path = "/opt/microsoft/omsconfig/Scripts/"
    if (sys.version_info.major == 2) :
        if (sys.version_info.minor >= 6) :
            automation_worker_path += "2.6x-2.7x"
        else:
            automation_worker_path += "2.4x-2.5x"

    os.chdir(automation_worker_path)
    nxOMSAutomationWorker=imp.load_source("nxOMSAutomationWorker", "./Scripts/nxOMSAutomationWorker.py")
    settings = nxOMSAutomationWorker.read_settings_from_mof_json(resourceSetting)
    if not settings.auto_register_enabled:
        write_log_output("HybridWorkerStatusCheck", LogLevel.FAILED, "Hybrid worker is not running")
        write_log_output("HybridWorkerStatusCheck", LogLevel.DEBUG, "Update Management solution is not enabled. ResourceSettings:" + resourceSetting)
        return

    if nxOMSAutomationWorker.Test_Marshall(resourceSetting) == [0]:
        write_log_output("HybridWorkerStatusCheck", LogLevel.SUCCESS, "Hybrid worker is running")
    else:
        write_log_output("HybridWorkerStatusCheck", LogLevel.FAILED, "Hybrid worker is not running")
        write_log_output("HybridWorkerStatusCheck", LogLevel.DEBUG, "ResourceSettings:" + resourceSetting + " read from current_mof file:(" + current_mof + ")")
        write_log_output("HybridWorkerStatusCheck", LogLevel.DEBUG, "nxOMSAutomationWorker.py path:" + automation_worker_path)

def check_hybrid_worker_package_present():
    if os.path.isfile("/opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/VERSION") and \
       os.path.isfile("/opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/DSCResources/MSFT_nxOMSAutomationWorkerResource/automationworker/worker/configuration.py"):
        write_log_output("HybridWorkerPackgeCheck", LogLevel.SUCCESS, "Hybrid worker package is present")
    else:
        write_log_output("HybridWorkerPackgeCheck", LogLevel.FAILED, "Hybrid worker package is not present")

def check_oms_agent_running():
    is_oms_agent_running, ps_output = is_process_running("omsagent", ["omsagent.log", "omsagent.conf"], "OMS Agent")
    if is_oms_agent_running:
        write_log_output("OMSAgentStatusCheck", LogLevel.SUCCESS, "OMS Agent is running")
    else:
        write_log_output("OMSAgentStatusCheck", LogLevel.FAILED, "OMS Agent is not running")
        write_log_output("OMSAgentStatusCheck", LogLevel.DEBUG, ps_output)

def is_process_running(process_name, search_criteria, output_name):
    grep_output = os.popen("ps aux | grep " + process_name).read()
    if any(search_text in grep_output for search_text in search_criteria):
        return True, grep_output
    else:
        return False, grep_output

def get_workspace():
    line = find_line_in_path("WORKSPACE", oms_admin_conf_path)
    if line is not None:
        return line.split("=")[1].strip()

    return None

def get_machine_info():
    hostname_output = os.popen("hostnamectl").read()
    write_log_output("GetMachineInfo", LogLevel.DEBUG, "Machine Information:\n" + hostname_output)

def is_fairfax_region():
    oms_endpoint = find_line_in_path("OMS_ENDPOINT", oms_admin_conf_path)
    if oms_endpoint is not None:
        return ".us" in oms_endpoint.split("=")[1]

def find_line_in_path(search_text, path, file_encoding=""):
    if os.path.isfile(path):
        if file_encoding == "":
            current_file = open(path, "r")
        else:
            current_file = codecs.open(path, "r", file_encoding)

        for line in current_file:
            if search_text in line:
                current_file.close()
                return line
    
        current_file.close()
    return None

def main(output_path=None, return_json_output="False"):
    if os.geteuid() != 0:
        print "Please run this script in sudo"
        exit()

    ## supported python version 2.4.x to 2.7.x
    if not ((sys.version_info[0] == 2) and ((sys.version_info[1]>=4) and (sys.version_info[1] < 8))):
	print("Unsupport python version:" + str(sys.version_info))
	exit()

    # initialize the rule_info list
    tmp_init_rule_info_list()

    get_machine_info()
    check_os()
    check_oms_agent_installed()
    check_oms_agent_running()
    check_hybrid_worker_package_present()
    check_hybrid_worker_running()
    check_network_endpoints()

    if return_json_output == "True":
        print json.dumps([obj.__dict__ for obj in rule_info_list])
    else:
        print "".join(output)
        if output_path is not None:
            try: 
                os.makedirs(output_path)
            except OSError:
                if not os.path.isdir(output_path):
                    raise
            log_path = output_path + "/healthcheck-" + str(datetime.datetime.utcnow().isoformat()) + ".log"
            f = open(log_path, "w")
            f.write("".join(output))
            print "Output is written to " + log_path

if __name__ == "__main__":
    if len(sys.argv) > 2:
        main(sys.argv[1], sys.argv[2])
    elif len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        main()
