import os
import subprocess

# A03:Injection — OS Command Injection
# User-controlled input concatenated directly into a shell command

def ping_host(hostname):
    command = "ping -c 4 " + hostname
    return os.system(command)

def get_file_info(filename):
    output = subprocess.check_output("file " + filename, shell=True)
    return output.decode()
