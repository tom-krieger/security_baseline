# @summary 
#    Create a cron job to search binaries with s-bit
#
# Create a fact with all auditd rules needed to monitor the usage of s-bit programs.
#
# @param include 
#     Directories to include into search. Can not be set together with parameter exclude.
#
# @param exclude 
#     Directories to exclude from search. Can not be set together with parameter include.
#
# @param auditd_rules_fact_file
#    File to write the auditd rules facts into.
#
# @param suid_fact_file 
#    File to write the suid program facts into.
#
# @param  sgid_fact_file
#    File to etite the sgid program facts into.
#
# @example
#   include security_baseline::auditd_suid_rules_cron
class security_baseline::auditd_suid_rules_cron (
  Array $include                 = [],
  Array $exclude                 = [],
  String $auditd_rules_fact_file = '/tmp/auditd.facts.yaml',
  String $suid_fact_file         = '/tmp/suid_programs.yaml',
  String $sgid_fact_file         = '/tmp/sgid_progras.yaml',
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
    $tmp_include = "${include.join(' ')}"
      concat::fragment {'suid_cron_body':
      target  => '/etc/cron.daily/suid-audit',
      content => epp('security_baseline/suid_auditd_include.epp', { 'include' => $tmp_include}),
      order   => 10,
    }
  }

  concat::fragment {'suid_cron_end':
    target  => '/etc/cron.daily/suid-audit',
    content => epp('security_baseline/suid_auditd_end.epp', {
      'auditd_rules_fact_file' => $auditd_rules_fact_file,
      'suid_fact_file'         => $suid_fact_file,
      'sgid_fact_file'         => $sgid_fact_file
    }),
    order   => 99,
  }
}
