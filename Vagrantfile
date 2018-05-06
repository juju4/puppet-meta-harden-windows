# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"
ENV['VAGRANT_DEFAULT_PROVIDER'] = 'virtualbox'

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
    config.vm.box = "mwrock/Windows2016"
    config.vm.guest = :windows
    config.vm.communicator = "winrm"
    config.vm.boot_timeout = 600

    config.vm.provision :puppet do |puppet|
       puppet.manifest_file = "init.pp"
       puppet.modules_path = "../"
       #puppet.options = "--verbose --debug"
       #puppet.facter = { 'fqdn' => config.vm.hostname }
    end

    config.vm.define "vhardenwinp" do |cfg|
        cfg.vm.hostname = "vhardenwinp"
        cfg.vm.provider "virtualbox" do |v|
          v.memory = 2048
          v.cpus = 2
          v.gui = true
        end
    end

end

