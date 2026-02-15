import json
import pprint
import pathlib
import os,os.path
from pathlib import Path

def get_user_auth_times(user_id):
    """
    Returns a list of the date and time of logins for user userid from log/auth.log.x
    """
    #print(os.listdir('project-1-network-log-analysis-CooperDonnell/log'))
    times = []
    path = 'project-1-network-log-analysis-CooperDonnell/log' # Tells where the logs are
    for filename in os.listdir('project-1-network-log-analysis-CooperDonnell/log'): 
        if 'auth.log' in filename: #checks if this is in the log folder
            with open(os.path.join(path, filename), 'r') as file:
                lines = file.readlines()
                for line in lines:
                    if user_id in line:    #userid is the parameter on the top! 
                        times.append(line[:15])


    return times


# Get all user ids that are failed logins with invalid user names. Return a dictionary mapping the userid to the number of invalid attempts.
def get_invalid_logins():
    """
    Returns a dictionary mapping invalid user ids to # of failed logins on log/auth.log.x
    """
    invalid_users = {}
    path = 'project-1-network-log-analysis-CooperDonnell/log' # Tells where the logs are
    for filename in os.listdir('project-1-network-log-analysis-CooperDonnell/log'): 
        if 'auth.log' in filename: #checks if this is in the log folder
            with open(os.path.join(path, filename), 'r') as file:
                lines = file.readlines()
                for line in lines:
                    if "Invalid user" in line:
                        parts = line.split() # splits line by spaces
                        if "from" in parts:
                            user = parts[parts.index("user") + 1] # Finds where user is because "Invalid user"  and "from" indicates a failed log in. Adds 1 so it gets the word after user which is the userid!
                            if user in invalid_users:
                                invalid_users[user] += 1
                            else:
                                invalid_users[user] = 1


    return invalid_users


# Find all IP addresses for invalid logins, then see which IPs are also used for scanning
def compare_invalid_IPs():
    ''' '''
    invalid_ips = []
    scanning_ips = []
    both = []
    path = 'project-1-network-log-analysis-CooperDonnell/log' # Tells where the logs are
    for filename in os.listdir('project-1-network-log-analysis-CooperDonnell/log'): 
        if 'auth.log' in filename: #checks if this is in the log folder
            with open(os.path.join(path, filename), 'r') as file:
                lines = file.readlines()
                for line in lines:
                    parts = line.split()
                    if "Invalid user" in line and "from" in parts:
                        ip = parts[parts.index("from") + 1]
                        invalid_ips.append(ip)
        if 'ufw.log' in filename: #checks if this is in the log folder
            with open(os.path.join(path, filename), 'r') as file:
                lines = file.readlines()
                for line in lines:
                    parts = line.split()
                    if "[UFW BLOCK]" in line and "SRC=" in line:
                        for part in parts:  
                            if part.startswith("SRC="):
                                scan_ip = part.split("=")[1]
                                scanning_ips.append(scan_ip)
    both = []
    for ip in invalid_ips:
        if ip in scanning_ips:
            both.append(ip)
    print(set(scanning_ips))
    print(set(both))

    return both




if __name__=="__main__":
    
    print(get_user_auth_times("tmoore"))
    print(get_invalid_logins())
    compare_invalid_IPs()
    #extract_log_files("ufw.log")
    #extract_log_files("auth.log")
    
