class { 'ds389':
  key_password  => '78x5C6uhp1T6',
  nssdb_pass    => 'm8polEd0WLOh',
  cert_name     => 'cert',
  rootdnpasswd  => '9Qrx1ede4yDF',
  dminpasswd    => 'vH1mz3WL15xa',
  repl_pass     => 'dv13Yh65XYo3',
  suffix        => 'dc=example,dc=com',
  ssl_ca_source => https://letsencrypt.org/certs/isrgrootx1.pem.txt
}
