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

## Troubleshooting & Known issues

* vagrant execution
It requires few changes like allow vagrant network login to execute. Check site.pp.

## License

BSD 2-clause
