class ds389 (
  String $key_password                 = undef,
  String $nssdb_pass                   = undef,
  String $cert_name                    = 'cert',
  String $rootdnpasswd                 = undef,
  String $adminpasswd                  = undef,
  String $repl_pass                    = undef,
  String $suffix                       = undef,
  String $ssl_key_location             = undef,
  String $ssl_cert_location            = undef,
  String $ssl_intermediate_location    = undef,
  String $ssl_ca_source                = undef,
  Boolean $master                      = true,
  Optional[String] $userdir_ldapurl    = undef,
  String $configdir_ldapurl            = "ldap://${::fqdn}:389/o=netscapeRoot",
  Optional[String] $replicaid          = undef,
  Optional[String] $replication_host   = undef,
  ){
  include ::pam

  exec { 'ssl_cert_presence':
    command => '/bin/true',
    onlyif  => "/usr/bin/test -e ${ssl_cert_location}",
  }
  exec { 'ssl_key_presence':
    command => '/bin/true',
    onlyif  => "/usr/bin/test -e ${ssl_key_location}",
  }
  exec { 'ssl_intermediate_presence':
    command => '/bin/true',
    onlyif  => "/usr/bin/test -e ${ssl_intermediate_location}",
  }
  $instance     = "slapd-${::hostname}"
  $instance_dir = "/etc/dirsrv/${instance}"
  $certdir = $instance_dir
  $replication_aggrement = "${::hostname}-${replication_host}"
  sysctl { 'net.ipv4.tcp_keepalive_time': value => '300' }

  $packages = [
    '389-ds-base',
    '389-admin',
    '389-ds-console',
  ]

  package { $packages:
    ensure => present,
  }

  file { 'setup.inf':
    path    => '/tmp/setup.inf',
    content => template("${module_name}/setup.inf.erb"),
    require => [
      File['ssl.ldif'],
      File['rsa.ldif'],
      File['netscaperootdb.ldif'],
      File['replica.ldif'],
      File['repluser.ldif'],
      File['changelog.ldif'],
      File['replagreement.ldif'],
    ]
  }

  exec { $instance:
    creates => "/etc/dirsrv/${instance}",
    command => "/usr/sbin/setup-ds-admin.pl --file=/tmp/setup.inf --silent --logfile=/etc/dirsrv/${instance}.log",
    require => [
        File['setup.inf'],
        Sysctl['net.ipv4.tcp_keepalive_time'],
      ]
  }

  $ssl_ca_location = '/etc/pki/tls/certs/dirsrv-ca.pem'

  file { 'globalsign-root':
    ensure  => 'present',
    path    => $ssl_ca_location,
    require => Exec[$instance],
    source  => $ssl_ca_source,
  }

  file { 'pin.txt':
    content => "Internal (Software) Token:${nssdb_pass}",
    path    => "${certdir}/pin.txt",
    require => Exec[$instance],
    owner   => 'dirsrv',
  }

  nsstools::create { $certdir:
    owner          => 'dirsrv',
    group          => 'dirsrv',
    mode           => '0660',
    password       => $key_password,
    manage_certdir => false,
    enable_fips    => false,
    require        => [
      File['globalsign-root'],
      Exec['ssl_cert_presence'],
      Exec['ssl_key_presence'],
      Exec['ssl_intermediate_presence'],
    ]
  }

  nsstools::add_cert { 'ca':
    certdir => $certdir,
    cert    => $ssl_ca_location,
    require => Nsstools::Create[$certdir],
  }

  nsstools::add_cert { 'intermediate':
    certdir => $certdir,
    cert    => $ssl_intermediate_location,
    require => Nsstools::Add_cert['ca'],
  }

  nsstools::add_cert_and_key{ $cert_name:
    certdir => $certdir,
    cert    => $ssl_cert_location,
    key     => $ssl_key_location,
    require => Nsstools::Add_cert['intermediate'],
  }

  file { 'ssl.ldif':
    path    => 'tmp/ssl.ldif',
    content => template("${module_name}/ssl.ldif.erb"),
  }

  file { 'rsa.ldif':
    path    => 'tmp/rsa.ldif',
    content => template("${module_name}/rsa.ldif.erb"),
  }

  file { 'netscaperootdb.ldif':
    path    => 'tmp/netscaperootdb.ldif',
    content => template("${module_name}/netscaperootdb.ldif.erb"),
  }
  file { 'replica.ldif':
    path    => 'tmp/replica.ldif',
    content => template("${module_name}/replica.ldif.erb"),
  }
  file { 'replagreement.ldif':
    path    => 'tmp/replagreement.ldif',
    content => template("${module_name}/replagreement.ldif.erb"),
  }
  file { 'replica-admin.ldif':
    path    => 'tmp/replica-admin.ldif',
    content => template("${module_name}/replica-admin.ldif.erb"),
  }
  file { 'replagreement-admin.ldif':
    path    => 'tmp/replagreement-admin.ldif',
    content => template("${module_name}/replagreement-admin.ldif.erb"),
  }
  file { 'repluser.ldif':
    path    => 'tmp/repluser.ldif',
    content => template("${module_name}/repluser.ldif.erb"),
  }
  file { 'changelog.ldif':
    path    => 'tmp/changelog.ldif',
    content => template("${module_name}/changelog.ldif.erb"),
  }

  file { '98scSpecials.ldif':
    path    => "/etc/dirsrv/${instance}/schema/98scSpecials.ldif",
    source  => "puppet:///modules/${module_name}/98scSpecials.ldif",
    notify  => Service["dirsrv@${::hostname}"],
    require => Exec[$instance],
  }

  exec { "${instance}-ssl":
    command => "/usr/bin/ldapmodify -x -D \"cn=Directory Manager\" -w ${rootdnpasswd} -f /tmp/ssl.ldif -H 'ldap://localhost'",
    unless  => "/usr/bin/grep 'nsslapd-security: on' ${instance_dir}/dse.ldif",
    require => [ Exec[$instance], Nsstools::Add_cert_and_key[$cert_name] ],
    notify  => Service["dirsrv@${::hostname}"],
  }

  exec { "${instance}-rsa":
    command => "/usr/bin/ldapmodify -x -D \"cn=Directory Manager\" -w ${rootdnpasswd} -f /tmp/rsa.ldif -H 'ldap://localhost'",
    unless  => "/usr/bin/grep 'nsSSLActivation: on' ${instance_dir}/dse.ldif",
    require => [
        Exec["${instance}-ssl"],
      ],
    notify  => Service["dirsrv@${::hostname}"],
  }

  if false {
    exec { "${instance}-admin-replica":
      command => "/usr/bin/ldapmodify -x -D \"cn=Directory Manager\" -w ${rootdnpasswd} -f /tmp/replica-admin.ldif -H 'ldap://localhost'",
      unless  => "/usr/bin/grep 'cn=replica,cn=\"o=netscaperoot\",cn=mapping tree,cn=config' ${instance_dir}/dse.ldif",
      require => [
          Exec["${instance}-rsa"],
        ],
      notify  => Service["dirsrv@${::hostname}"],
    }


    exec { "${instance}-admin-replagreement":
      command => "/usr/bin/ldapmodify -x -D \"cn=Directory Manager\" -w ${rootdnpasswd} -f /tmp/replagreement-admin.ldif -H 'ldap://localhost'",
      unless  => "/usr/bin/grep 'cn=<%= @replication_aggrement %>,cn=replica,cn=\"o=netscaperoot\",cn=mapping tree,cn=config' ${instance_dir}/dse.ldif",
      require => [
          Exec["${instance}-admin-replica"],
        ],
      notify  => Service["dirsrv@${::hostname}"],
    }
  }
  service { "dirsrv@${hostname}":
    ensure  => 'running',
    require => [ File['pin.txt'] ],
  }


  if $osfamily == 'redhat' {
    firewalld_rich_rule { 'Accept ldaps port':
      ensure => present,
      zone   => 'public',
      port   => {
        'port'     => 636,
        'protocol' => 'tcp',
      },
      action => 'accept',
    }
    firewalld_rich_rule { 'Accept ldap port':
      ensure => present,
      zone   => 'public',
      port   => {
        'port'     => 389,
        'protocol' => 'tcp',
      },
      action => 'accept',
    }
    firewalld_rich_rule { 'Accept http admin port':
      ensure => present,
      zone   => 'public',
      port   => {
        'port'     => 9830,
        'protocol' => 'tcp',
      },
      action => 'accept',
    }
  }

}
