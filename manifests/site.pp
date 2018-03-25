node default {
  #include windows_autoupdate

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
    ensure_enable_windows_ntp_server_is_set_to_disabled => true
  }

  windows_eventlog { 'Application':
    log_path => '%SystemRoot%\system32\winevt\Logs\Application.evtx',
    # 512MB
    log_size => '536870912',
    max_log_policy => 'overwrite'
  }

  windows_eventlog { 'System':
    log_path => '%SystemRoot%\system32\winevt\Logs\Application.evtx',
    log_size => '536870912',
    max_log_policy => 'overwrite'
  }

  windows_eventlog { 'Security':
    log_path => '%SystemRoot%\system32\winevt\Logs\Application.evtx',
    log_size => '536870912',
    max_log_policy => 'overwrite'
  }

  windows_eventlog { 'Windows PowerShell':
    log_size => '536870912',
    max_log_policy => 'overwrite'
  }

  windows_eventlog { 'Microsoft-Windows-PowerShell/Operational':
    log_size => '536870912',
    max_log_policy => 'overwrite'
  }

  class { 'windows_firewall': ensure => 'running' }
  windows_firewall::exception { 'WINRM':
    ensure       => present,
    direction    => 'in',
    action       => 'Allow',
    enabled      => 'yes',
    protocol     => 'TCP',
    local_port   => '5985',
    remote_port  => 'any',
    display_name => 'Windows Remote Management HTTP-In',
    description  => 'Inbound rule for Windows Remote Management via WS-Management. [TCP 5985]',
  }

  windowsfeature { 'NET-Framework-Core':
    ensure => present,
  }

  # windows-audit
  registry_value { 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit\ProcessCreationIncludeCmdLine_Enabled':
    ensure     => present,
    type       => dword,
    data       => 1,
  }

  #  windows-ie
  registry_value { 'HKLM\Software\Policies\Microsoft\Internet Explorer\Main\Isolation64Bit':
    ensure     => present,
    type       => dword,
    data       => 1,
  }
  registry_value { 'HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings\Zones\3\270C':
    ensure     => present,
    type       => dword,
    data       => 0,
  }

  # llmnr-101: LLMNR mitigations
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
#  $dangerousext = ['hta', 'vbe', 'vbs', 'VBE', 'js', 'jse', 'sct', 'wsc', 'wsf', 'wsh', 'pif', 'jar']
#  $dangerousext.each |String $ext| {
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
#  }
#
#  $dangerousextcmd = ['HKCR\\htafile\\shell\\open\\command', 'HKCR\\VBSFile\\shell\\edit\\command', 'HKCR\\VBSFile\\shell\\open\\command', 'HKCR\\VBSFile\\shell\\open2\\command', 'HKCR\\VBEFile\\shell\\edit\\command', 'HKCR\\VBEFile\\shell\\open\\command', 'HKCR\\VBEFile\\shell\\open2\\command', 'HKCR\\JSFile\\shell\\open\\command', 'HKCR\\JSEFile\\shell\\open\\command', 'HKCR\\wshfile\\shell\\open\\command', 'HKCR\\scriptletfile\\shell\\open\\command' ]
#  $dangerousextcmd.each |String $extcmd| {
#    registry_value { "Extension ${extcmd}":
#      path       => "${extcmd}",
#      ensure     => present,
#      value      => '(default)',
#      type       => string,
#      data       => '%windir%\system32\notepad.exe',
#    }
#  }

  # services-1: Services to be disabled
  registry_value { 'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\SMB1':
    ensure     => present,
    type       => dword,
    data       => 0,
  }

  # wpad-101: WPAD mitigations
  registry_key { 'HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad':
    ensure => present,
  }
  registry_value { 'HKLM\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad\WpadOverride':
    ensure     => present,
    type       => dword,
    data       => 1,
  }
}
