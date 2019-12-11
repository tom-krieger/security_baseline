# @summary 
#    Create a cron job to search binaries with s-bit
#
# Create a fact with all auditd rules needed to monitor the usage of s-bit programs.
#
# @example
#   include security_baseline::auditd_suid_rules_cron
class security_baseline::auditd_suid_rules_cron (
  Array $include                 = [],
  Array $exclude                 = [],
  String $auditd_rules_fact_file = '/tmp/auditd.facts.yaml'
) {
  if(!empty($include) and !empty($exclude)) {
    fail('Please include directories or exclude them but you can not do both!')
  }

  concat { '/etc/cron.daily/suid-audit':
    ensure => present,
    owner  => 'root',
    group  => 'root',
    mode   => '0700',
  }

  concat::fragment {'suid_cron_top':
    target  => '/etc/cron.daily/suid-audit',
    content => epp('security_baseline/suid_auditd_top.epp', { 'auditd_rules_fact_file' => $auditd_rules_fact_file}),
    order   => 01,
  }

  if(empty($include)) {
    $tmp_include = ''

    if(empty($exclude)) {
      $tmp_exclude = ''
    } else {
      $tmp_exclude = "-e ${exclude.join('-e ')}"
    }

    concat::fragment {'suid_cron_body':
      target  => '/etc/cron.daily/suid-audit',
      content => epp('security_baseline/suid_auditd_exclude.epp', { 'exclude' => $tmp_exclude}),
      order   => 10,
    }

  } else {
    $tmp_include = "-e ${include.join(' ')}"
      concat::fragment {'suid_cron_body':
      target  => '/etc/cron.daily/suid-audit',
      content => epp('security_baseline/suid_auditd_include.epp', { 'include' => $tmp_include}),
      order   => 10,
    }
  }

  concat::fragment {'suid_cron_end':
    target  => '/etc/cron.daily/suid-audit',
    content => epp('security_baseline/suid_auditd_end.epp', { 'auditd_rules_fact_file' => $auditd_rules_fact_file}),
    order   => 99,
  }
}
