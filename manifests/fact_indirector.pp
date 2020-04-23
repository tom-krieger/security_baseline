# @summary
#    Configure sending facts to logstash
#
# Setup sending summary facts from secutity_baseline to logstash
#
# @param configure_logstash
#    If set to true the facts indirevtor to logstash will be configured. This requires Puppet Enterprise
#
# @param logstash_host
#    The logstash host to send facts to
#
# @param logstash_port
#    The port logstash is listening
#
# @param logstash_timeout
#    The timeout for sendding facts to logstash.
#
# @example
#   include security_baseline::fact_indirector
class security_baseline::fact_indirector (
  String $logstash_host,
  Boolean $configure_logstash = false,
  Integer $logstash_port      = 5999,
  Integer $logstash_timeout   = 1000,
) {
  if empty($logstash_host) {
    fail('Logstash host missing.')
  }

  if $configure_logstash and $::is_pe {
    file { '/etc/puppetlabs/puppet/security_baseline.yaml':
      ensure  => file,
      owner   => 'pe-puppet',
      group   => 'pe-puppet',
      mode    => '0644',
      content => epp('security_baseline/security_baseline.yaml.epp', {
        host    => $logstash_host,
        port    => $logstash_port,
        timeout => $logstash_timeout,
      }),
    }

    file { '/etc/puppetlabs/puppet/security_baseline_routes.yaml':
      ensure  => file,
      owner   => 'pe-puppet',
      group   => 'pe-puppet',
      mode    => '0640',
      content => epp('security_baseline/security_baseline_routes.yaml.epp', {
        facts_terminus       => 'puppetdb',
        facts_cache_terminus => 'security_baseline'
      }),
      notify  => Service['pe-puppetserver'],
    }

    ini_setting { 'enable security_baseline_routes.yaml':
      ensure  => present,
      path    => '/etc/puppetlabs/puppet/puppet.conf',
      section => 'master',
      setting => 'route_file',
      value   => '/etc/puppetlabs/puppet/security_baseline_routes.yaml',
      require => File['/etc/puppetlabs/puppet/security_baseline_routes.yaml'],
      notify  => Service['pe-puppetserver'],
    }
  }
}
