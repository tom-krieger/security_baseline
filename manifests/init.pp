# @summary 
#    Security baseline enforcement and monitoring
#
# Define a complete security baseline and monitor the rules. The definition of the baseline can be done in Hiera. 
# The purpose of the module is to give the ability to setup complete security baseline which not necessarily have to stick 
# to an industry security guide like the CIS benchmarks.  
# One main purpose is to ensure the module can be extended by further security settings and monitorings without changing the code of
# this module.
#
# The easiest way to use the module is to put all rule data into a hiera file. For more information please coinsult the README file.
#
# @param baseline_version
#    Version of the security ruleset
#
# @param rules
#    Hash containing the wholw ruleset
#
# @param debug
#    Switch debug output on
#
# @param log_info
#    Switch logging with level info on
#
# @param logfile
#    Logfile to write messages to
#
# @param set_postrun
#    Set postrun_command in pupet agent
#
# @example
#   include security_baseline
#
class security_baseline (
  String $baseline_version,
  Hash $rules,
  Boolean $debug                              = false,
  Boolean $log_info                           = false,
  String $logfile                             = '/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml',
  Boolean $set_postrun                        = true,
  Array $auditd_suid_include                  = [],
  Array $auditd_suid_exclude                  = [],
  String $auditd_rules_file                   = '/etc/audit/rules.d/sec_baseline_auditd.rules',
  Enum['fact', 'csv_file'] $reporting_type    = 'fact',
  String $auditd_rules_fact_file              = '/opt/puppetlabs/facter/facts.d/security_baseline_auditd.yaml',
  Boolean $update_postrun_command             = true,
  String $fact_upload_command                 = '/usr/local/bin/puppet facts upload',
) {
  include ::security_baseline::services
  include ::security_baseline::system_file_permissions_cron
  include ::security_baseline::world_writeable_files_cron
  include ::security_baseline::unowned_files_cron

  if($debug) {
    echo { "Applying security baseline version: ${baseline_version}":
      loglevel => 'debug',
      withpath => false,
    }
  }

  class { '::security_baseline::config':
    update_postrun_command => $update_postrun_command,
    fact_upload_command    => $fact_upload_command,
    reporting_type         => $reporting_type,
    before                 => Concat[$logfile],
  }

  class {'security_baseline::auditd_suid_rules_cron':
    include                => $auditd_suid_include,
    exclude                => $auditd_suid_exclude,
    auditd_rules_fact_file => $auditd_rules_fact_file,
    before                 => Concat[$logfile],
  }

  if ($reporting_type == 'fact') {
    concat { $logfile:
      ensure => present,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }

    concat::fragment { 'start':
      content => epp('security_baseline/logfile_start.epp', {'version' => $baseline_version}),
      target  => $logfile,
      order   => 1,
    }
  } elsif ($reporting_type == 'csv_file') {
    concat { $logfile:
      ensure => present,
      owner  => 'root',
      group  => 'root',
      mode   => '0644',
    }
    concat::fragment { 'start':
      content => epp('security_baseline/csv_file_start.epp', {}),
      target  => $logfile,
      order   => 1,
    }
  }

  create_resources('::security_baseline::sec_check', $rules)

  if ($reporting_type == 'fact') {
    concat::fragment { 'finish':
      content => epp('security_baseline/logfile_end.epp', {}),
      target  => $logfile,
      order   => 9999,
    }
  } elsif ($reporting_type == 'csv_file') {
    concat::fragment { 'finish':
      content => epp('security_baseline/csv_file_end.epp', {}),
      target  => $logfile,
      order   => 9999,
    }
  }
}
