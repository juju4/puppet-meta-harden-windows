# https://forge.puppet.com/puppetlabs/iis
# https://puppet.com/blog/deploying-iis-and-aspnet-puppet
# https://www.metaltoad.com/blog/managing-iis-configuration-puppet-powershell-dsc

$iis_features = ['Web-WebServer','Web-Scripting-Tools', 'Web-Http-Errors', 'Web-Http-Logging', 'Web-Filtering']
#$iis_features = ['Web-WebServer','Web-Scripting-Tools', 'Web-Http-Errors', 'Web-Http-Logging', 'Web-Filtering', 'Web-Asp-Net45', 'NET-Framework-45-ASPNET']
$cert_fqdn = 'test.contoso.com'
$webroot = 'c:\\inetpub\\complete'

iis_feature { $iis_features:
  ensure => 'present',
  include_management_tools => true,
  include_all_subfeatures => false,
}

# Delete the default website to prevent a port binding conflict.
iis_site {'Default Web Site':
  ensure  => absent,
  require => Iis_feature['Web-WebServer'],
}

# Create self-signed certificate
exec { 'self-signed-certificate':
  command   => "New-SelfSignedCertificate -DnsName ${cert_fqdn} -CertStoreLocation cert:\\LocalMachine\\My",
  unless    => "if (Get-ChildItem -Path cert:\\LocalMachine\\My -Recurse -DNSName \"${cert_fqdn}\") { exit 1 }",
  provider  => powershell,
}
# How-to recover: Get-ChildItem -Path cert:\\LocalMachine\\My -Recurse -DNSName \"${cert_fqdn}\" | fl Thumbprint
#   and send in variable to use further
exec { 'self-signed-certificate-to-facts':
  command   => "(Get-ChildItem -Path cert:\\LocalMachine\\My -Recurse -DNSName \"${cert_fqdn}\" | Fl -property Thumbprint | Out-string).trim().Replace('Thumbprint : ', 'webserver_certhash=') | Out-File -Encoding ASCII C:\\ProgramData\\PuppetLabs\\facter\\facts.d\\webserver_certhash.txt",
  unless    => "if (Test-Path -Path \"C:\\ProgramData\\PuppetLabs\\facter\\facts.d\\webserver_certhash.txt\") { exit 1 }",
  provider  => powershell,
}

# Create User/Group
group { 'IISCompleteGroup':
   ensure => present,
}

# Create Directories

file { "${webroot}":
  ensure => 'directory'
}

file { 'c:\\inetpub\\complete_vdir':
  ensure => 'directory'
}

# Set Permissions

acl { "${webroot}":
  permissions => [
    {'identity' => 'IISCompleteGroup', 'rights' => ['read', 'execute']},
  ],
}

acl { 'c:\\inetpub\\complete_vdir':
  permissions => [
    {'identity' => 'IISCompleteGroup', 'rights' => ['read', 'execute']},
  ],
}

iis_application_pool { 'complete_site_app_pool':
  ensure                  => 'present',
  state                   => 'started',
  managed_pipeline_mode   => 'Integrated',
  managed_runtime_version => 'v4.0',
  auto_start              => true,
  enable32_bit_app_on_win64 => false,
# default: 20 (min)
  idle_timeout            => 00:20:00,
# To load web.config. normally in web root folder
#  enable_configuration_override => true,
# https://docs.microsoft.com/en-us/iis/get-started/planning-your-iis-architecture/getting-started-with-configuration-in-iis-7-and-above
# https://msdn.microsoft.com/en-us/library/bb763179.aspx
}

iis_application_pool {'test_app_pool':
    ensure                    => 'present',
    enable32_bit_app_on_win64 => true,
    managed_runtime_version   => '""',
    managed_pipeline_mode     => 'Classic',
    start_mode                => 'AlwaysRunning'
  }

iis_site { 'complete':
  ensure           => 'started',
  physicalpath     => "${webroot}",
  applicationpool  => 'complete_site_app_pool',
  enabledprotocols => [ 'http', 'https' ],
  bindings         => [
    {
      'bindinginformation'   => '*:80:',
      'protocol'             => 'http',
    },
    {
      'bindinginformation'   => '*:443:',
      'protocol'             => 'https',
      'certificatehash'      => $facts['webserver_certhash'],
      'certificatestorename' => 'MY',
      'sslflags'             => 1,
    },
  ],
  require => File["${webroot}"],
}

iis_virtual_directory { 'vdir':
  ensure       => 'present',
  sitename     => 'complete',
  physicalpath => 'c:\\inetpub\\complete_vdir',
  require      => File['c:\\inetpub\\complete_vdir'],
}

# https://www.ryadel.com/en/iis-web-config-secure-http-response-headers-pass-securityheaders-io-scan/
file { 'c:\\inetpub\\web.config':
  content => "<system.webServer>
  <httpProtocol>
    <customHeaders>
      <!-- SECURITY HEADERS - https://securityheaders.io/? -->
      <!-- Protects against Clickjacking attacks. ref.: http://stackoverflow.com/a/22105445/1233379 -->
      <add name=\"X-Frame-Options\" value=\"SAMEORIGIN\" />
      <!-- Protects against Clickjacking attacks. ref.: https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet -->
      <add name=\"Strict-Transport-Security\" value=\"max-age=31536000; includeSubDomains\"/>
      <!-- Protects against XSS injections. ref.: https://www.veracode.com/blog/2014/03/guidelines-for-setting-security-headers/ -->
      <add name=\"X-XSS-Protection\" value=\"1; mode=block\" />
      <!-- Protects against MIME-type confusion attack. ref.: https://www.veracode.com/blog/2014/03/guidelines-for-setting-security-headers/ -->
      <add name=\"X-Content-Type-Options\" value=\"nosniff\" />
      <!-- CSP modern XSS directive-based defence, used since 2014. ref.: http://content-security-policy.com/ -->
      <add name=\"Content-Security-Policy\" value=\"default-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'self'; upgrade-insecure-requests;\" />
      <!-- Prevents from leaking referrer data over insecure connections. ref.: https://scotthelme.co.uk/a-new-security-header-referrer-policy/ -->
      <add name=\"Referrer-Policy\" value=\"strict-origin\" />
    </customHeaders>
  </httpProtocol>
</system.webServer>",
}

# https://blogs.msdn.microsoft.com/varunm/2013/04/23/remove-unwanted-http-response-headers/
# https://ruslany.net/2008/07/scripting-url-rewrite-module-configuration/
# or chocolatey: urlrewrite
#class { 'iis_rewrite':
##  package_source_location => 'http://myhost.com/package231.msi'
#}

file { "${webroot}\\.well-known":
  ensure    => directory,
}
file { "${webroot}\\.well-known\\security.txt":
  ensure    => present,
  content   => "Contact: mailto:security@example.com
Contact: +1-201-555-0123
Contact: https://example.com/security
Encryption: https://example.com/pgp-key.txt
Disclosure: Full
Acknowledgement: https://example.com/hall-of-fame.html",
}

# https://docs.microsoft.com/en-us/iis/web-hosting/web-server-for-shared-hosting/application-pool-identity-as-anonymous-user
# https://kevinareed.com/2015/11/07/how-to-deploy-anything-in-iis-with-zero-downtime-on-a-single-server/
