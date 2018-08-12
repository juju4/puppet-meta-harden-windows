[![Build Status - Master](https://travis-ci.org/juju4/puppet-meta-harden-windows.svg?branch=master)](https://travis-ci.org/juju4/puppet-meta-harden-windows)
[![Build Status - Devel](https://travis-ci.org/juju4/puppet-meta-harden-windows.svg?branch=devel)](https://travis-ci.org/juju4/puppet-meta-harden-windows/branches)
[![Appveyor - Master](https://ci.appveyor.com/api/projects/status/0s0n3ml7douaon7r/branch/master?svg=true)](https://ci.appveyor.com/project/juju4/puppet-meta-harden-windows)
![Appveyor - Devel](https://ci.appveyor.com/api/projects/status/0s0n3ml7douaon7r/branch/devel?svg=true)

# puppet meta harden windows

## Module Description
This module uses a compilation of other modules to do hardening of Windows system.
You are advised to use network shares to store files.

### Operating systems

This module is targeted for Windows.

## Continuous integration

you can test this role with Appveyor or Vagrant.

```
$ cd /path/to/
$ vagrant up
$ vagrant provision
$ vagrant destroy
```

Role has also a packer config which allows to create image for virtualbox, vmware or azure template.

```
# load subscription settings or from file
$ . ~/.azure/credentials
$ packer build azure-windows_server_2016.json
$ packer build -var-file=variables.json azure-windows_server_2016.json
$ packer build -only=virtualbox-iso windows_server_2016.json
## if you want to enable extra log
$ PACKER_LOG_PATH="packerlog.txt" PACKER_LOG=1 packer build azure-windows_server_2016.json
```

See also
* https://www.packer.io/docs/builders/azure.html
* https://www.packer.io/docs/provisioners/puppet-masterless.html
* https://www.packer.io/docs/templates/user-variables.html

## Troubleshooting & Known issues

* vagrant execution
It requires few changes like allow vagrant network login to execute. Check site.pp.

## License

BSD 2-clause
