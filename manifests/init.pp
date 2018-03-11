# init.pp
class harden_windows {

  if $facts[osfamily] == 'windows' {
    notice('Running hardening on Windows')
    include ::harden_windows
  } else {
    notice('Unsupported osfamily')
  }
}
