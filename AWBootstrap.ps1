# Add DNS for elastic
Add-Content 'C:\Windows\System32\Drivers\etc\hosts' "10.0.0.10 elastic-8-6-agent"

# Unpack the archive
Expand-Archive C:\vagrant\elastic-agent-8.6.1-windows-x86_64.zip -DestinationPath 'C:\Program Files\'
Expand-Archive C:\vagrant\Sysmon.zip -DestinationPath 'C:\Program Files\'


# Install the agent
& 'C:\Program Files\elastic-agent-8.6.1-windows-x86_64\elastic-agent.exe' install -f --url=https://elastic-8-6-agent:8220 --certificate-authorities='C:\vagrant\ca.crt' --enrollment-token=$(Get-Content C:\vagrant\WAEtoken.txt)
& 'C:\Program Files\Sysmon64.exe' -accepteula -i