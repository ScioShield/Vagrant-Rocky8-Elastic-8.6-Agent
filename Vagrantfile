Vagrant.configure("2") do |config|
  config.vm.define "elastic" do |elastic|
    elastic.vm.box = "bento/rockylinux-8.7"
    elastic.vm.hostname = 'elastic-8-6-agent'
    elastic.vm.box_url = "bento/rockylinux-8.7"
    elastic.vm.provision :shell, path: "ESBootstrap.sh"
    elastic.vm.network :private_network, ip:"192.168.56.10"
    elastic.vm.network :forwarded_port, guest: 5601, host: 5601, host_ip: "0.0.0.0", id: "kibana", auto_correct: true
    elastic.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--cpus", 4]
      v.customize ["modifyvm", :id, "--memory", 8192]
      v.customize ["modifyvm", :id, "--name", "elastic-8-6-agent"]
    end
  end
  config.vm.define "linux", autostart: false do |linux|
    linux.vm.box = "bento/rockylinux-8.7"
    linux.vm.hostname = 'linux-agent-8-6'
    linux.vm.box_url = "bento/rockylinux-8.7"
    linux.vm.provision :shell, path: "ALBootstrap.sh"
    linux.vm.network :private_network, ip: "192.168.56.20"
    linux.vm.provider :virtualbox do |v|
      v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
      v.customize ["modifyvm", :id, "--cpus", 1]
      v.customize ["modifyvm", :id, "--memory", 1024]
      v.customize ["modifyvm", :id, "--name", "linux-agent-8-6"]
    end
  end
  config.vm.define "windows", autostart: false do |windows|
    windows.vm.box = "gusztavvargadr/windows-10-21h2-enterprise"
    windows.vm.hostname = 'windows-agent-8-6'
    windows.vm.box_url = "gusztavvargadr/windows-10-21h2-enterprise"
    windows.vm.provision :shell, privileged: "true", path: "AWBootstrap.ps1"
    windows.vm.network :private_network, ip: "192.168.56.30"
    windows.vm.provider :virtualbox do |v|
     v.customize ["modifyvm", :id, "--natdnshostresolver1", "on"]
     v.customize ["modifyvm", :id, "--cpus", 2]
     v.customize ["modifyvm", :id, "--memory", 4096]
     v.customize ["modifyvm", :id, "--name", "windows-agent-8-6"]
    end
  end
end