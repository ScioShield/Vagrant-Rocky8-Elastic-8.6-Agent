# Vagrant Rocky8 Elastic-8.6 Agent

## Blog  
Post - TBD  

## Requirements
RAM - 13GB  
CPU - 8 vCores  

## Setup  
Vagrantfile to setup single node ES + Kib + Fleet cluster  
Bring up either Windows or Linux or both hosts with the following commands  
The elastic cluster has to be started first  
### Elastic + Windows
<code>vagrant up elastic windows</code>  
### Elastic + Linux  
<code>vagrant up elastic linux</code>  
### Elastic + Linux + Windows
<code>vagrant up elastic linux windows</code>  
To login run
### Elastic  
<code>vagrant ssh elastic</code>
### Linux  
<code>vagrant ssh linux</code>
### Windows  
<code>vagrant ssh windows</code>

### DNS settings
Used for remote deployments
Replace (Vagrant host ip) with the IP of the host machine you will run Vagrant from  
Windows Powershell  
<code>Add-Content 'C:\Windows\System32\Drivers\etc\hosts' "(Vagrant host ip) elastic-8-6-agent"</code>  
Linux Bash  
<code>echo "(Vagrant host ip) elastic-8-6-agent" >> /etc/hosts</code>  

## Kibana  
Log into Kibana (local)  
<code>https://10.0.0.10:5601</code>  
<code>https://127.0.0.1:5601</code>  
Log into Kibana (remote)  
<code>https://elastic-8-6-agent:5601</code>  
  
Username: <code>elastic</code>  
The password is in a file called "Password.txt" in the directory you ran Vagrant from,  
this is the password to the super user account.  
The password is printed to the console / terminal you ran <code>vagrant up</code> from.  

## TODO
Change <code>echo</code> to <code>printf</code>  
Normalize all the <code>curl</code> calls  
Add automation for "Custom Windows Event Logs" integration