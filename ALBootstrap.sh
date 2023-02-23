#!/usr/bin/env bash
# This will only work on Centos 7 (it has not been tested on other distros)
echo "10.0.0.10 elastic-8-6-agent" >> /etc/hosts
# unpack the agent
tar -xvf /vagrant/elastic-agent-8.6.1-linux-x86_64.tar.gz -C /opt/

# Check if Kibana is reachable 
kcheck=$(curl -L --silent --output /dev/null --cacert /vagrant/ca.crt -XGET 'https://elastic-8-6-agent:5601' --write-out %{http_code})
until [ $kcheck -eq 200 ]
do
  echo "Checking if Kibana is reachable, retrying..."
  sleep 5
done
echo "Kibana is reachable"

# Install the agent
sudo /opt/elastic-agent-8.6.1-linux-x86_64/elastic-agent install -f \
  --url=https://elastic-8-6-agent:8220 \
  --enrollment-token=$(cat /vagrant/LAEtoken.txt) \
  --certificate-authorities=/vagrant/ca.crt