node default {
  #include windows_autoupdate
  include chocolatey

  class { 'harden_windows_server':
    is_domain_controller => false,
    ensure_turn_on_mapper_io_lltdio_driver_is_set_to_disabled => true,
    ensure_turn_on_responder_rspndr_driver_is_set_to_disabled => true,
    ensure_turn_off_microsoft_peer_to_peer_networking_services_is_set_to_enabled => true,
    ensure_prohibit_installation_and_configuration_of_network_bridge_on_your_dns_domain_network_is_set_to_enabled => true,
    ensure_require_domain_users_to_elevate_when_setting_a_networks_location_is_set_to_enabled => true,
    ensure_hardened_unc_paths_is_set_to_enabled_with_require_mutual_authentication_and_require_integrity_for_all_netlogon_and_sysvol_shares => true,
    disable_ipv6_ensure_tcpip6_parameter_disabledcomponents_is_set_to_0xff255 => true,
    ensure_configuration_of_wireless_settings_using_windows_connect_now_is_set_to_disabled => true,
    ensure_prohibit_access_of_the_windows_connect_now_wizards_is_set_to_enabled => true,
    ensure_apply_uac_restrictions_to_local_accounts_on_network_logons_is_set_to_enabled => true,
    ensure_wdigest_authentication_is_set_to_disabled => true,
    ensure_include_command_line_in_process_creation_events_is_set_to_disabled => true,
    ensure_allow_remote_access_to_the_plug_and_play_interface_is_set_to_disabled => true,
    ensure_configure_registry_policy_processing_do_not_apply_during_periodic_background_processing_is_set_to_enabled_false => true,
    ensure_configure_registry_policy_processing_process_even_if_the_group_policy_objects_have_not_changed_is_set_to_enabled_true => true,
    ensure_turn_off_background_refresh_of_group_policy_is_set_to_disabled => true,
    ensure_turn_off_downloading_of_print_drivers_over_http_is_set_to_enabled => true,
    ensure_turn_off_handwriting_personalization_data_sharing_is_set_to_enabled => true,
    ensure_turn_off_handwriting_recognition_error_reporting_is_set_to_enabled => true,
    ensure_turn_off_internet_connection_wizard_if_url_connection_is_referring_to_microsoftcom_is_set_to_enabled => true,
    ensure_turn_off_internet_download_for_web_publishing_and_online_ordering_wizards_is_set_to_enabled => true,
    ensure_turn_off_internet_file_association_service_is_set_to_enabled => true,
    ensure_turn_off_printing_over_http_is_set_to_enabled => true,
    ensure_turn_off_registration_if_url_connection_is_referring_to_microsoftcom_is_set_to_enabled => true,
    ensure_turn_off_search_companion_content_file_updates_is_set_to_enabled => true,
    ensure_turn_off_the_order_prints_picture_task_is_set_to_enabled => true,
    ensure_turn_off_the_publish_to_web_task_for_files_and_folders_is_set_to_enabled => true,
    ensure_turn_off_the_windows_messenger_customer_experience_improvement_program_is_set_to_enabled => true,
    ensure_turn_off_windows_customer_experience_improvement_program_is_set_to_enabled => true,
    ensure_turn_off_windows_error_reporting_is_set_to_enabled => true,
    ensure_always_use_classic_logon => true,
    ensure_require_a_password_when_a_computer_wakes_on_battery_is_set_to_enabled => true,
    ensure_require_a_password_when_a_computer_wakes_plugged_in_is_set_to_enabled => true,
    ensure_configure_offer_remote_assistance_is_set_to_disabled => true,
    ensure_configure_solicited_remote_assistance_is_set_to_disabled => true,
    ensure_enable_rpc_endpoint_mapper_client_authentication_is_set_to_enabled => true,
    ensure_restrict_unauthenticated_rpc_clients_is_set_to_enabled_authenticatied => true,
    ensure_microsoft_support_diagnostic_tool_turn_on_msdt_interactive_communication_with_support_provider_is_set_to_disabled => true,
    ensure_enable_disable_perftrack_is_set_to_disabled => true,
    ensure_enable_windows_ntp_client_is_set_to_enabled => true,
    ensure_enable_windows_ntp_server_is_set_to_disabled => true,

    # re-evaluate. some might be defined later
    ensure_add_workstations_to_domain_is_set_to_administrators => true,
    configure_allow_log_on_through_remote_desktop_services => false,
    ensure_act_as_part_of_the_operating_system_is_set_to_no_one => false,
    configure_access_this_computer_from_the_network => false,
    ensure_access_credential_manager_as_a_trusted_caller_is_set_to_no_one => false,
    # only if hyper-v is present
    configure_create_symbolic_links => false,
  }

  # requirement for powershell install
  dsc_service{'wuauserv':
    dsc_startuptype => 'Automatic',
    dsc_name => 'wuauserv',
    dsc_state  => 'Running'
  }

  # chocolatey install (default for Windows)
  $chocolatey_packages = ['powershell', 'osquery', 'git', 'sysinternals' ]
# FIXME! vagrant crash with chocolatey packages install. appveyor OK
# FIXME! LAPS not available/pending package fix https://chocolatey.org/packages/laps
#  $chocolatey_packages = []
  $chocolatey_packages.each |String $pkg| {
    package { "${pkg}":
      ensure   => latest,
      provider => chocolatey,
#      source   => 'https://<internal_repo>/chocolatey',
    }
  }
  package { "sysmon":
      ensure   => latest,
      provider => chocolatey,
#      source   => 'https://<internal_repo>/chocolatey',
# https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon v8.0 vs https://chocolatey.org/packages/sysmon 7.01
      install_options   => ['--checksum64', '706F3D26475C8CCC0252E9E4FC7D5BF7CBAB872094ED52BB267DA45022BD6533', '--checksum', '706F3D26475C8CCC0252E9E4FC7D5BF7CBAB872094ED52BB267DA45022BD6533']
  }

  file { 'sysmonconfig.xml':
    path    => 'c:/windows/temp/sysmonconfig.xml',
    ensure  => file,
#    source  => "puppet:///modules/puppet-meta-harden-windows/sysmonconfig-export.xml",
    source  => "${facts['filetemp_path']}\\sysmonconfig-export.xml",
  }
  exec { 'Load sysmon config':
    command   => 'c:\ProgramData\chocolatey\lib\sysmon\tools\sysmon.exe -n -accepteula -i c:\windows\temp\sysmonconfig.xml',
    onlyif    => 'C:\Windows\System32\cmd.exe /c "if exist "c:\ProgramData\chocolatey\lib\sysmon\tools\sysmon.exe" (exit 0) else (exit 1)"'
  }

  # logging
  windows_eventlog { 'Application':
    log_path => '%SystemRoot%\system32\winevt\Logs\Application.evtx',
    # 512MB
    log_size => '536870912',
    max_log_policy => 'overwrite'
  }

  windows_eventlog { 'System':
    log_path => '%SystemRoot%\system32\winevt\Logs\System.evtx',
    log_size => '536870912',
    max_log_policy => 'overwrite'
  }

  windows_eventlog { 'Security':
    log_path => '%SystemRoot%\system32\winevt\Logs\Security.evtx',
    log_size => '536870912',
    max_log_policy => 'overwrite'
  }

  windows_eventlog { 'Setup':
    log_path => '%SystemRoot%\system32\winevt\Logs\Setup.evtx',
    log_size => '536870912',
    max_log_policy => 'overwrite'
  }

  windows_eventlog { 'Windows Powershell':
    log_size => '536870912',
    max_log_policy => 'overwrite'
  }

  $eventlogs = [ 'Microsoft-Windows-PowerShell/Operational', 'Microsoft-Windows-WMI-Activity/Operational', 'Microsoft-Windows-Sysmon/Operational', 'Microsoft-Windows-AppLocker/EXE and DLL', 'Microsoft-Windows-AppLocker/MSI and Script', 'Microsoft-Windows-AppLocker/Packaged app-Deployment', 'Microsoft-Windows-AppLocker/Packaged app-Execution', 'Microsoft-Windows-TaskScheduler/Operational', 'Microsoft-Windows-DNS-Client/Operational' ]
  $eventlogs.each |String $log| {
    # FIXME!
#    windows_eventlog { "${log}":
#      log_size => '536870912',
#      max_log_policy => 'overwrite'
#    }
    dsc_registry {"${log}":
      dsc_ensure => 'Present',
      dsc_key => "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels\\${log}",
      dsc_valuename => 'MaxSize',
      dsc_valuedata => '536870912',
      dsc_valuetype => 'Dword',
    }
  }

  class { 'windows_firewall': ensure => 'running' }
  windows_firewall::exception { 'WINRM':
    ensure       => present,
    direction    => 'in',
    action       => 'allow',
    enabled      => true,
    protocol     => 'TCP',
    local_port   => 5985,
    remote_port  => 'any',
    display_name => 'Windows Remote Management HTTP-In',
    description  => 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]',
  }

  # FIXME! execute fine in appveyor but breaks under vagrant. not really required for security.
#  windowsfeature { 'NET-Framework-Core':
#    ensure => present,
#  }

  # FIXME!
#  win_service { 'iphlpsvc':
#       ensure             => 'present',
#       binary_path_name   => 'C:\Windows\System32\svchost.exe -k NetSvcs',
#       start_type         => 'disabled',
#  }
#  win_service { 'WinHttpAutoProxySvc':
#       ensure             => 'present',
#       binary_path_name   => 'C:\Windows\system32\svchost.exe -k LocalService',
#       start_type         => 'disabled',
#  }
  dsc_service{'iphlpsvc':
    dsc_startuptype => 'Disabled',
    dsc_name => 'iphlpsvc',
    dsc_state  => 'stopped'
  }
  dsc_service{'WinHttpAutoProxySvc':
    dsc_startuptype => 'Disabled',
    dsc_name => 'WinHttpAutoProxySvc',
    dsc_state  => 'stopped'
  }

  # windows-base
  registry_value { 'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares':
    ensure     => present,
    type       => array,
    data       => [''],
  }

  registry_value { 'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinClientSec':
    ensure     => present,
    type       => dword,
    data       => 537395248,
  }

  registry_value { 'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\NtlmMinServerSec':
    ensure     => present,
    type       => dword,
    data       => 537395248,
  }

  # windows-audit
  registry_key { 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe':
    ensure => present,
  }
  registry_value { 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe\AuditLevel':
    ensure     => present,
    type       => dword,
    data       => 8,
  }

  registry_value { 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled':
    ensure     => present,
    type       => dword,
    data       => 1,
  }

  if ($facts['kernelmajversion'] >= 10) {
# https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-group-membership, Win10/2016+
  auditpol { 'Group Membership':
    success => 'enable',
    failure => 'disable',
  }

# https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-pnp-activity, Win10/2016+
  auditpol { 'PNP Activity':
    success => 'enable',
    failure => 'disable',
  }
  }

  auditpol { 'Removable Storage':
    success => 'enable',
    failure => 'enable',
  }

  auditpol { 'Other Account Logon Events':
    success => 'enable',
    failure => 'enable',
  }

  auditpol { 'Distribution Group Management':
    success => 'enable',
    failure => 'enable',
  }

  #  windows-ie
  registry_key { 'HKLM\Software\Policies\Microsoft\Internet Explorer\Main':
    ensure => present,
  }
  registry_value { 'HKLM\Software\Policies\Microsoft\Internet Explorer\Main\Isolation64Bit':
    ensure     => present,
    type       => dword,
    data       => 1,
  }
  registry_key { 'HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3':
    ensure => present,
  }
  registry_value { 'HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\270C':
    ensure     => present,
    type       => dword,
    data       => 0,
  }

  # laps
  registry_key { 'HKLM\Software\Microsoft\Policies\Microsoft Services\AdmPwd':
    ensure => present,
  }
  registry_value { 'HKLM\Software\Microsoft\Policies\Microsoft Services\AdmPwd\AdmPwdEnabled':
    ensure     => present,
    type       => dword,
    data       => 1,
  }

  # windows-account
# FIXME!
  local_security_policy { 'Allow log on through Remote Desktop Services':
    ensure         => 'present',
    policy_setting => 'SeRemoteInteractiveLogonRight',
    policy_type    => 'Privilege Rights',
    # policy_value   => '*S-1-5-32-544',
    policy_value   => 'Administrators',
  }

#  # cis-access-cred-manager
#  local_security_policy { 'Access Credential Manager as a trusted caller':
#    ensure         => 'present',
#    policy_setting => 'SeTrustedCredManAccessPrivilege',
#    policy_type    => 'Privilege Rights',
#    # policy_value   => '*S-1-0-0',
#    policy_value   => 'Nobody',
#  }
#
#  # cis-act-as-os
#  local_security_policy { 'Act as part of the operating system':
#    ensure         => 'present',
#    policy_setting => 'SeTcbPrivilege',
#    policy_type    => 'Privilege Rights',
#    # policy_value   => '*S-1-0-0',
#    policy_value   => 'Nobody',
#  }

  # cis-add-workstations (harden_windows_server: ensure_add_workstations_to_domain_is_set_to_administrators)
  # FIXME! still not applied
#  local_security_policy { 'Add workstations to domain':
#    ensure         => 'present',
#    policy_setting => 'SeMachineAccountPrivilege',
#    policy_type    => 'Privilege Rights',
#    policy_value   => '*S-1-5-32-544',
#  }

  # llmnr-101: LLMNR mitigations
  registry_key { 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient':
    ensure => present,
  }
  registry_value { 'HKLM\Software\Policies\Microsoft\Windows NT\DNSClient\EnableMulticast':
    ensure     => present,
    type       => dword,
    data       => 0,
  }

  # Mimikatz protection
  registry_value { 'HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential':
    ensure     => present,
    type       => dword,
    data       => 0,
  }

  registry_value { 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\FilterAdministratorToken':
    ensure     => present,
    type       => dword,
    data       => 1,
  }

  registry_value { 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy':
    ensure     => present,
    type       => dword,
    data       => 0,
  }

  # powershell-module-logging: PowerShell Module Logging
  registry_key { 'HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging':
    ensure => present,
  }
  registry_value { 'HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\EnableModuleLogging':
    ensure     => present,
    type       => dword,
    data       => 1,
  }
  registry_key { 'HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames':
    ensure => present,
  }
  registry_value { 'HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames\*':
    ensure     => present,
    type       => string,
    data       => '*',
  }
  registry_key { 'HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging':
    ensure => present,
  }
  registry_value { 'HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\EnableScriptBlockLogging':
    ensure     => present,
    type       => dword,
    data       => 1,
  }
  registry_key { 'HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription':
    ensure => present,
  }
  registry_value { 'HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription\EnableTranscripting':
    ensure     => present,
    type       => dword,
    data       => 1,
  }
  # FIXME! nok windowsfeature, nok dsc_windowsfeature...
#  windowsfeature { 'MicrosoftWindowsPowerShellV2':
#    ensure => absent,
#  }
#  dsc_windowsfeature {'MicrosoftWindowsPowerShellV2':
#    dsc_ensure => 'absent',
#    dsc_name   => 'MicrosoftWindowsPowerShellV2',
#  }

  # microsoft-online-accounts: Microsoft Online Accounts
  registry_key { 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount':
    ensure => present,
  }
  registry_value { 'HKLM\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowYourAccount\value':
    ensure     => present,
    type       => dword,
    data       => 0,
  }

  registry_key { 'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore':
    ensure => present,
  }
  registry_value { 'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\AutoDownload':
    ensure     => present,
    type       => dword,
    data       => 4,
  }

  registry_value { 'HKLM\SOFTWARE\Policies\Microsoft\WindowsStore\DisableOSUpgrade':
    ensure     => present,
    type       => dword,
    data       => 1,
  }

  registry_key { 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search':
    ensure => present,
  }
  registry_value { 'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search\AllowIndexingEncryptedStoresOrItems':
    ensure     => present,
    type       => dword,
    data       => 0,
  }

  registry_value { 'HKLM\SYSTEM\CurrentControlSet\Control\FileSystem\NtfsDisableLastAccessUpdate':
    ensure     => present,
    type       => dword,
    data       => 0,
  }

  registry_value { 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher':
    ensure     => present,
    type       => dword,
    data       => 3,
  }

  registry_value { 'HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnableSuperfetch':
    ensure     => present,
    type       => dword,
    data       => 3,
  }

  # wsh-101: Review potentially dangerous extensions association
  # puppetlabs/registry: Limitations: Keys within HKEY_LOCAL_MACHINE (hklm), HKEY_CLASSES_ROOT (hkcr) or HKEY_USERS (hku) are supported. Other predefined root keys (e.g., HKEY_CURRENT_USER) are not currently supported.
  # puppetlabs/dsc: DSC Resources are executed under the SYSTEM context by default, which means you are unable to access any user level Registry key without providing alternate credentials.
  $dangerousext = ['hta', 'vbe', 'vbs', 'VBE', 'js', 'jse', 'sct', 'wsc', 'wsf', 'wsh', 'pif', 'jar']
  $dangerousext.each |String $ext| {
#    registry_value { "Extension ${ext}":
#      path       => "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.${ext}",
#      ensure     => present,
#      value      => '(default)',
#      type       => string,
#      data       => '%windir%\system32\notepad.exe',
#    }
#    registry_value { "Extension ${ext} OpenWithList":
#      path       => "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.${ext}\\OpenWithList",
#      ensure     => present,
#      value      => 'a',
#      type       => string,
#      data       => '%windir%\system32\notepad.exe',
#    }
    dsc_registry {"registry_ext_${ext}":
      dsc_ensure => 'Present',
      dsc_key => "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.${ext}",
      dsc_valuename => '(default)',
      dsc_valuedata => '%windir%\system32\notepad.exe',
    }
    dsc_registry {"registry_ext_${ext}_OpenWithList":
      dsc_ensure => 'Present',
      dsc_key => "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\.${ext}\\OpenWithList",
      dsc_valuename => 'a',
      dsc_valuedata => '%windir%\system32\notepad.exe',
    }
  }

  $dangerousextcmd = ['HKCR:\\htafile\\shell\\open\\command', 'HKCR:\\VBSFile\\shell\\edit\\command', 'HKCR:\\VBSFile\\shell\\open\\command', 'HKCR:\\VBSFile\\shell\\open2\\command', 'HKCR:\\VBEFile\\shell\\edit\\command', 'HKCR:\\VBEFile\\shell\\open\\command', 'HKCR:\\VBEFile\\shell\\open2\\command', 'HKCR:\\JSFile\\shell\\open\\command', 'HKCR:\\JSEFile\\shell\\open\\command', 'HKCR:\\wshfile\\shell\\open\\command', 'HKCR:\\scriptletfile\\shell\\open\\command' ]
  $dangerousextcmd.each |String $extcmd| {
#    registry_value { "Extension ${extcmd}":
#      path       => "${extcmd}",
#      ensure     => present,
#      value      => '(default)',
#      type       => string,
#      data       => '%windir%\system32\notepad.exe',
#    }
    dsc_registry {"registry_ext_${extcmd}":
      dsc_ensure => 'Present',
      dsc_key => "${extcmd}",
      dsc_valuename => '(default)',
      dsc_valuedata => '%windir%\system32\notepad.exe',
    }
  }

  # services-1: Services to be disabled
  registry_value { 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1':
    ensure     => present,
    type       => dword,
    data       => 0,
  }
  # FIXME!
#  windowsfeature { 'SMB1Protocol':
#    ensure => absent,
#  }
#  dsc_windowsfeature {'SMB1Protocol':
#    dsc_ensure => 'absent',
#    dsc_name   => 'SMB1Protocol',
#  }

  # wpad-101: WPAD mitigations
  registry_key { 'HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad':
    ensure => present,
  }
  registry_value { 'HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad\WpadOverride':
    ensure     => present,
    type       => dword,
    data       => 1,
  }

  # tls12
  $proto_enable = ['TLS 1.2']
  $proto_disable = ['SSL 2.0', 'SSL 3.0']
  $proto_enable.each |String $proto| {
    dsc_registry {"Client-${proto}-DisabledByDefault":
      dsc_ensure => 'Present',
      dsc_key => "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\${proto}\\Client",
      dsc_valuename => 'DisabledByDefault',
      dsc_valuedata => '0',
      dsc_valuetype => 'Dword',
    }
    dsc_registry {"Client-${proto}-Enabled":
      dsc_ensure => 'Present',
      dsc_key => "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\${proto}\\Client",
      dsc_valuename => 'Enabled',
      dsc_valuedata => '1',
      dsc_valuetype => 'Dword',
    }
    dsc_registry {"Server-${proto}-DisabledByDefault":
      dsc_ensure => 'Present',
      dsc_key => "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\${proto}\\Server",
      dsc_valuename => 'DisabledByDefault',
      dsc_valuedata => '0',
      dsc_valuetype => 'Dword',
    }
    dsc_registry {"Server-${proto}-Enabled":
      dsc_ensure => 'Present',
      dsc_key => "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\${proto}\\Server",
      dsc_valuename => 'Enabled',
      dsc_valuedata => '1',
      dsc_valuetype => 'Dword',
    }
  }
  $proto_disable.each |String $proto| {
    dsc_registry {"Client-${proto}-DisabledByDefault":
      dsc_ensure => 'Present',
      dsc_key => "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\${proto}\\Client",
      dsc_valuename => 'DisabledByDefault',
      dsc_valuedata => '0',
      dsc_valuetype => 'Dword',
    }
    dsc_registry {"Client-${proto}-Enabled":
      dsc_ensure => 'Present',
      dsc_key => "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\${proto}\\Client",
      dsc_valuename => 'Enabled',
      dsc_valuedata => '0',
      dsc_valuetype => 'Dword',
    }
    dsc_registry {"Server-${proto}-DisabledByDefault":
      dsc_ensure => 'Present',
      dsc_key => "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\${proto}\\Server",
      dsc_valuename => 'DisabledByDefault',
      dsc_valuedata => '0',
      dsc_valuetype => 'Dword',
    }
    dsc_registry {"Server-${proto}-Enabled":
      dsc_ensure => 'Present',
      dsc_key => "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\${proto}\\Server",
      dsc_valuename => 'Enabled',
      dsc_valuedata => '0',
      dsc_valuetype => 'Dword',
    }
  }

  # https://technet.microsoft.com/en-us/library/cc976700.aspx
  # divergence between roles and inspec test
#  local_security_policy { 'Access this computer from the network':
#    ensure         => 'present',
#    policy_setting => 'SeNetworkLogonRight',
#    policy_type    => 'Privilege Rights',
#    # harden_windows_server: Administrators, Authenticated users + DC: Enterprise Domain Controllers
##    policy_value   => '*S-1-5-32-544,*S-1-5-11',
##    policy_value   => '*S-1-5-32-544,*S-1-5-11,*S-1-5-9',
#    # FIXME! vagrant user needed if vagrant. appveyor ok.
##    policy_value   => '*S-1-0-0',
#    policy_value   => 'Nobody',
##    policy_value   => '*S-1-0-0,vagrant',
#  }

   # already in harden_windows_server
#  local_security_policy { 'Create symbolic links':
#    ensure         => 'present',
#    policy_setting => 'SeCreateSymbolicLinkPrivilege',
#    policy_type    => 'Privilege Rights',
#    policy_value   => '*S-1-5-32-544',
#  }

  # msoffice

  # misc
  file { 'applocker.xml':
    path    => 'c:/windows/temp/applocker.xml',
    ensure  => file,
#    source  => "puppet:///modules/puppet-meta-harden-windows/applocker.xml",
    source  => "${facts['filetemp_path']}\\applocker.xml",
  }
  # FIXME! maybe issue under vagrant. appveyor ok.
  exec { 'Set-AppLockerPolicy':
    command   => 'Set-AppLockerPolicy -XMLPolicy c:\windows\temp\applocker.xml',
    provider  => powershell,
  }

  file { 'firewall.wfw':
    path    => 'c:/windows/temp/firewall.wfw',
    ensure  => file,
#    source  => "puppet:///modules/puppet-meta-harden-windows/firewall.wfw",
    source  => "${facts['filetemp_path']}\\firewall.wfw",
  }
  # FIXME! maybe issue under vagrant. appveyor ok.
  exec { 'Firewall import':
    command   => 'c:\windows\system32\netsh.exe advfirewall import c:\windows\temp\firewall.wfw',
  }

  # stig/iadgov
# FIXME! Munging failed
#  registry_value { 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI\EnumerateAdministrators':
#    ensure     => present,
#    type       => dword,
#    data       => 0,
#  }
  dsc_registry {"EnumerateAdministrators":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\CredUI',
    dsc_valuename => 'EnumerateAdministrators',
    dsc_valuedata => '0',
    dsc_valuetype => 'Dword',
  }

  registry_value { 'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry':
    ensure     => present,
    type       => dword,
    data       => 1,
  }

#  registry_value { 'HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services\fDisableCdm':
#    ensure     => present,
#    type       => dword,
#    data       => 1,
#  }
  dsc_registry {"fDisableCdm":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services',
    dsc_valuename => 'fDisableCdm',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  registry_value { 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature':
    ensure     => present,
    type       => dword,
    data       => 1,
  }

  registry_value { 'HKLM\SYSTEM\CurrentControlSet\Control\LSA\UseMachineId':
    ensure     => present,
    type       => dword,
    data       => 1,
  }

# FIXME!
# https://tickets.puppetlabs.com/browse/MODULES-3195
# https://tickets.puppetlabs.com/browse/MODULES-5011
#  registry_value { 'HKLM\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0\allownullsessionfallback':
#    ensure     => present,
#    type       => dword,
#    data       => 0,
#  }
  dsc_registry {"allownullsessionfallback":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA\MSV1_0',
    dsc_valuename => 'allownullsessionfallback',
    dsc_valuedata => '0',
    dsc_valuetype => 'Dword',
  }

#  registry_value { 'HKLM\SYSTEM\CurrentControlSet\Control\LSA\pku2u\AllowOnlineID':
#    ensure     => present,
#    type       => dword,
#    data       => 0,
#  }
  dsc_registry {"AllowOnlineID":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SYSTEM\CurrentControlSet\Control\LSA\pku2u',
    dsc_valuename => 'AllowOnlineID',
    dsc_valuedata => '0',
    dsc_valuetype => 'Dword',
  }

  registry_value { 'HKLM\SYSTEM\CurrentControlSet\Services\LDAP\LDAPClientIntegrity':
    ensure     => present,
    type       => dword,
    data       => 1,
  }

  dsc_registry {"The Windows Remote Management (WinRM) service must not store RunAs credentials.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\Software\Policies\Microsoft\Windows\WinRM\Service',
    dsc_valuename => 'DisableRunAs',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"InPrivate browsing in Microsoft Edge must be disabled.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main',
    dsc_valuename => 'AllowInPrivate',
    dsc_valuedata => '0',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Unauthenticated RPC clients must be restricted from connecting to the RPC server.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Rpc',
    dsc_valuename => 'RestrictRemoteClients',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"The machine inactivity limit must be set to 15 minutes, locking the system with the screensaver.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
    dsc_valuename => 'InactivityTimeoutSecs',
    dsc_valuedata => '900',
    dsc_valuetype => 'Dword',
  }

  # empty rule: ensure_hardened_unc_paths_is_set_to_enabled_with_require_mutual_authentication_and_require_integrity_for_all_netlogon_and_sysvol_shares
  dsc_registry {"Hardened UNC Paths must be defined to require mutual authentication and integrity - NETLOGON":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths',
    dsc_valuename => '\\\\*\NETLOGON',
    dsc_valuedata => 'RequireMutualAuthentication=1,RequireIntegrity=1',
  }
  dsc_registry {"Hardened UNC Paths must be defined to require mutual authentication and integrity - SYSVOL":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths',
    dsc_valuename => '\\\\*\SYSVOL',
    dsc_valuedata => 'RequireMutualAuthentication=1,RequireIntegrity=1',
  }

  dsc_registry {"Kerberos encryption types must be configured to prevent the use of DES and RC4 encryption suites":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters',
    dsc_valuename => 'SupportedEncryptionTypes',
    dsc_valuedata => '2147483640',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Camera access from the lock screen must be disabled.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization',
    dsc_valuename => 'NoLockScreenCamera',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"The display of slide shows on the lock screen must be disabled.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization',
    dsc_valuename => 'NoLockScreenSlideshow',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"IPv6 source routing must be configured to highest protection.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters',
    dsc_valuename => 'DisableIpSourceRouting',
    dsc_valuedata => '2',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"The system must be configured to prevent Internet Control Message Protocol (ICMP) redirects from overriding Open Shortest Path First (OSPF) generated routes.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters',
    dsc_valuename => 'EnableICMPRedirect',
    dsc_valuedata => '0',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"The system must be configured to ignore NetBIOS name release requests except from WINS servers.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters',
    dsc_valuename => 'NoNameReleaseOnDemand',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Insecure logons to an SMB server must be disabled.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation',
    dsc_valuename => 'AllowInsecureGuestAuth',
    dsc_valuedata => '0',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Wi-Fi Sense must be disabled.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config',
    dsc_valuename => 'AutoConnectAllowedOEM',
    dsc_valuedata => '0',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Downloading print driver packages over HTTP must be prevented.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers',
    dsc_valuename => 'DisableWebPnPDownload',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Web publishing and online ordering wizards must be prevented from downloading a list of providers.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
    dsc_valuename => 'NoWebServices',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Users must be prompted for a password on resume from sleep (on battery).":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings\0e796bdb-100d-47d6-a2d5-f7d2daa51f51',
    dsc_valuename => 'DCSettingIndex',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Local users on domain-joined computers must not be enumerated.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System',
    dsc_valuename => 'EnumerateLocalUsers',
    dsc_valuedata => '0',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"The network selection user interface (UI) must not be displayed on the logon screen.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System',
    dsc_valuename => 'DontDisplayNetworkSelectionUI',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Printing over HTTP must be prevented.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers',
    dsc_valuename => 'DisableHTTPPrinting',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Users must not be allowed to ignore SmartScreen filter warnings for unverified files in Microsoft Edge.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter',
    dsc_valuename => 'PreventOverrideAppRepUnknown',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Users must not be allowed to ignore SmartScreen filter warnings for malicious websites in Microsoft Edge.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter',
    dsc_valuename => 'PreventOverride',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Enhanced anti-spoofing when available must be enabled for facial recognition.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\Biometrics\FacialFeatures',
    dsc_valuename => 'EnhancedAntiSpoofing',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"The Application Compatibility Program Inventory must be prevented from collecting data and sending the information to Microsoft.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat',
    dsc_valuename => 'DisableInventory',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"The setting to allow Microsoft accounts to be optional for modern style apps must be enabled.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
    dsc_valuename => 'MSAOptional',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"The minimum pin length for Microsoft Passport for Work must be 6 characters or greater.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork\PINComplexity',
    dsc_valuename => 'MinimumPINLength',
    dsc_valuedata => '6',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"The use of a hardware security device with Windows Hello for Business must be enabled.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\PassportForWork',
    dsc_valuename => 'RequireSecurityDevice',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Signing in using a PIN must be turned off.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System',
    dsc_valuename => 'AllowDomainPINLogon',
    dsc_valuedata => '0',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"The system must be configured to prevent the storage of passwords and credentials.":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa',
    dsc_valuename => 'DisableDomainCreds',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Disable Windows Script Host":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings',
    dsc_valuename => 'Enabled',
    dsc_valuedata => '0',
    dsc_valuetype => 'Dword',
  }

  dsc_registry {"Disable Windows Script Host - IgnoreUserSettings":
    dsc_ensure => 'Present',
    dsc_key => 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings',
    dsc_valuename => 'IgnoreUserSettings',
    dsc_valuedata => '1',
    dsc_valuetype => 'Dword',
  }

  # acl permissions
#  acl { 'c:/':
#    permissions => [
#     { identity => 'Administrators', rights => ['full'] },
#     { identity => 'SYSTEM', rights => ['full'] },
#     { identity => 'Users', rights => ['read','execute'] },
#     { identity => 'Authenticated Users', rights => ['modify'] },
#    ],
#    purge => 'false',
#    inherit_parent_permissions => false,
#  }

#  reg_acl { 'hklm:software':
#    owner => 'Administrator',
#    permissions =>
#      [
#        {'RegistryRights' => 'FullControl', 'IdentityReference' => 'BUILTIN\Administrators' },
## FIXME! non-fatal errors at execution
#        {'RegistryRights' => 'FullControl', 'IdentityReference' => 'SYSTEM' },
#        {'RegistryRights' => 'FullControl', 'IdentityReference' => 'CREATOR OWNER' },
#        {'RegistryRights' => 'QueryValues,EnumerateSubKeys,Notify,ReadPermissions', 'IdentityReference' => 'ALL APPLICATION PACKAGES' },
#        {'RegistryRights' => 'QueryValues,EnumerateSubKeys,Notify,ReadPermissions', 'IdentityReference' => 'Users' },
#      ],
#    inherit_from_parent => false,
#   }
#
#  reg_acl { 'hklm:system':
#    owner => 'Administrator',
#    permissions =>
#      [
#        {'RegistryRights' => 'FullControl', 'IdentityReference' => 'BUILTIN\Administrators' },
#        {'RegistryRights' => 'FullControl', 'IdentityReference' => 'SYSTEM' },
#        {'RegistryRights' => 'FullControl', 'IdentityReference' => 'CREATOR OWNER' },
#        {'RegistryRights' => 'QueryValues,EnumerateSubKeys,Notify,ReadPermissions', 'IdentityReference' => 'ALL APPLICATION PACKAGES' },
#        {'RegistryRights' => 'QueryValues,EnumerateSubKeys,Notify,ReadPermissions', 'IdentityReference' => 'Users' },
#      ],
#    inherit_from_parent => false,
#   }

}
