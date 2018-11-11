# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"
ENV['VAGRANT_DEFAULT_PROVIDER'] = 'virtualbox'

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "mwrock/Windows2016"
  config.vm.hostname = "phardenwin"
  #config.vm.network "private_network", ip: "192.168.50.100"

  config.vm.guest = :windows
  config.vm.communicator = "winrm"
  config.vm.boot_timeout = 600

  config.vm.define "phardenwin" do |cfg|
    cfg.vm.hostname = "phardenwin"
    cfg.vm.provider "virtualbox" do |v|
      v.memory = 2048
      v.cpus = 2
      v.gui = true
    end
  end

  config.vm.synced_folder ".", "/vagrant"

# https://github.com/snandam/vagrant_windows_puppet/blob/master/Vagrantfile

  config.vm.provision "shell", inline: "(New-Object Net.WebClient).DownloadFile('https://downloads.puppetlabs.com/windows/puppet5/puppet-agent-5.5.6-x64.msi', 'c:\\users\\vagrant\\puppet-agent-5.5.6-x64.msi')"
  config.vm.provision "shell", inline: "cmd /c start /wait msiexec /i c:\\users\\vagrant\\puppet-agent-5.5.6-x64.msi /q /L* c:\\install-puppet.log", privileged: true
  config.vm.provision "shell", inline: "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile('https://github.com/juju4/harden_windows_server/archive/master.tar.gz', \"c:\\windows\\temp\\autostructure-harden_windows_server-HEAD.tar.gz\")"
  config.vm.provision "shell", inline: "[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile('https://github.com/kpn-puppet/puppet-kpn-local_security_policy/archive/3.1.1.tar.gz', \"c:\\windows\\temp\\puppet-kpn-local_security_policy-3.1.1.tar.gz\")"
  $modules = <<-EOF
puppet config print config
puppet config print modulepath
puppet module install puppetlabs-windows
puppet module install puppetlabs-powershell
puppet module install puppetlabs-registry
puppet module install puppetlabs-dsc
puppet module install puppet-windowsfeature
puppet module install puppet-windows_firewall
puppet module install puppet-windows_autoupdate
puppet module install puppet-windows_eventlog
puppet module install puppet-msoffice
puppet module install puppet-archive
#puppet module install autostructure-harden_windows_server
#puppet module install kpn-local_security_policy
puppet module install c:\\windows\\temp\\puppet-kpn-local_security_policy-3.1.1.tar.gz --ignore-dependencies
puppet module install autostructure-auditpol
puppet module install c:\\windows\\temp\\autostructure-harden_windows_server-HEAD.tar.gz --ignore-dependencies
puppet module install ocastle-win_service
puppet module install ipcrm-registry_acl --ignore-dependencies
puppet module install puppetlabs-iis
puppet module install opentable-iis_rewrite --ignore-dependencies
#puppet module install chocolatey-chocolatey
EOF
  config.vm.provision "shell", inline: $modules, privileged: true

  # issue mapping unix host to windows guest files...
  #config.vm.provision "shell", inline: "net use z: \\vboxsrv\vagrant", privileged: true
  config.vm.provision "shell", inline: "mkdir C:/ProgramData/PuppetLabs/code/environments/production/modules/harden_windows/manifests", privileged: true
  config.vm.provision "shell", inline: "mkdir C:/projects/puppet-meta-harden-windows/files", privileged: true
  config.vm.provision "file", source: "manifests/site.pp", destination: "c:\\ProgramData\\PuppetLabs\\code\\environments\\production\\manifests\\site.pp"
  config.vm.provision "file", source: "manifests/iis.pp", destination: "c:\\ProgramData\\PuppetLabs\\code\\environments\\production\\manifests\\iis.pp"
  config.vm.provision "file", source: "manifests/chocolatey.pp", destination: "c:\\ProgramData\\PuppetLabs\\code\\environments\\production\\manifests\\chocolatey.pp"
  config.vm.provision "file", source: "files/applocker.xml", destination: "c:\\projects\\puppet-meta-harden-windows\\files\\applocker.xml"
  config.vm.provision "file", source: "files/firewall.wfw", destination: "c:\\projects\\puppet-meta-harden-windows\\files\\firewall.wfw"
  config.vm.provision "file", source: "files/sysmonconfig-export.xml", destination: "c:\\projects\\puppet-meta-harden-windows\\files\\sysmonconfig-export.xml"
  #config.vm.provision "file", source: "manifests/init.pp", destination: "c:\\ProgramData\\PuppetLabs\\code\\environments\\production\\manifests\\init.pp"

#  hardenwin.vm.provision :puppet do |puppet|
#    puppet.manifest_file  = "site.pp"
#    #puppet.manifests_path  = "manifests"
#    #puppet.module_path = "../"
#    puppet.module_path = "modules"
#    puppet.options = "--verbose --debug"
#    # Need to set the fqdn here as well; see
#    # http://www.benjaminoakes.com/2013/04/25/making-puppets-fqdn_rand-play-nice-with-vagrant/
#    puppet.facter = { 'fqdn'  => hardenwin.vm.hostname }
#  end

  # go manual road...
  config.vm.provision "shell", inline: "puppet apply --modulepath='C:/ProgramData/PuppetLabs/code/environments/production/modules;C:/ProgramData/PuppetLabs/code/modules;C:/opt/puppetlabs/puppet/modules' c:\\ProgramData\\PuppetLabs\\code\\environments\\production\\manifests\\site.pp --disable_warnings deprecations --verbose", privileged: true
  config.vm.provision "shell", inline: "puppet apply --modulepath='C:/ProgramData/PuppetLabs/code/environments/production/modules;C:/ProgramData/PuppetLabs/code/modules;C:/opt/puppetlabs/puppet/modules' c:\\ProgramData\\PuppetLabs\\code\\environments\\production\\manifests\\iis.pp --disable_warnings deprecations --verbose", privileged: true

end
