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
#    Hash containing the whole ruleset
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
# @param summary_report
#    File to write a summary report yaml report
#
# @param auditd_suid_include
#    Directories to search for suid and sgid programs. Can not be set together with auditd_suid_exclude
#
# @param auditd_suid_exclude
#    Directories to exclude from search for suid and sgid programs. Can not be set together with auditd_suid_include
#
# @param auditd_rules_file
#    Files to write the auditd rules facts into.
#
# @param reporting_type
#    Select to type of reporting. ca currently be set to csv or fact.
#
# @param reports
#    Select which reports to produce.
#
# @param auditd_rules_fact_file
#    The file where to store the facts for auditd rules
#
# @param suid_fact_file
#    The file where to store the suid programms
#
# @param sgid_fact_file
#    The file where to store the sgid programs
#
# @param update_postrun_command
#    Update Puppet agent post run command
#
# @param fact_upload_command
#    Command to use to upload facts to Puppet master
#
# @param reboot
#    If set to true and there are classes with the reboot flag set to true a reboot will
#    be performef if these classed fire
#
# @param reboot_timeout
#    Timeout until reboot will take place
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
  String $summary_report                      = '/opt/puppetlabs/facter/facts.d/security_baseline_summary.yaml',
  Array $auditd_suid_include                  = [],
  Array $auditd_suid_exclude                  = [],
  String $auditd_rules_file                   = '/etc/audit/rules.d/sec_baseline_auditd.rules',
  Enum['fact', 'csv_file'] $reporting_type    = 'fact',
  Enum['summary', 'details', 'both'] $reports = 'both',
  String $auditd_rules_fact_file              = '/opt/puppetlabs/facter/facts.d/security_baseline_auditd.yaml',
  String $suid_fact_file                      = '/opt/puppetlabs/facter/facts.d/security_baseline_suid_programs.yaml',
  String $sgid_fact_file                      = '/opt/puppetlabs/facter/facts.d/security_baseline_sgid_programs.yaml',
  Boolean $update_postrun_command             = true,
  String $fact_upload_command                 = '/usr/local/bin/puppet facts upload',
  Boolean $reboot                             = false,
  Integer $reboot_timeout                     = 60,
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
  }

  class {'security_baseline::auditd_suid_rules_cron':
    include                => $auditd_suid_include,
    exclude                => $auditd_suid_exclude,
    auditd_rules_fact_file => $auditd_rules_fact_file,
    suid_fact_file         => $suid_fact_file,
    sgid_fact_file         => $sgid_fact_file,
  }

  if ($reports == 'both' or $reports == 'details') {
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
  } elsif ($reports == 'summary') {
    file { $logfile:
      ensure => absent,
    }
  }

  create_resources('::security_baseline::sec_check', $rules)

  if($reports == 'both' or $reports == 'summary') {
    $summary = security_baseline::summary("/tmp/security_baseline_summary_${::hostname}.txt", true)

    if empty($summary) {
      echo { 'no-summary-data':
        message  => 'no summary data',
        loglevel => 'warning',
        withpath => false,
      }
    } else {
      file { $summary_report:
        ensure  => file,
        content => epp('security_baseline/summary_report.epp', {
          compliant         => $summary['ok'],
          failed            => $summary['fail'],
          unknown           => $summary['unknown'],
          compliant_count   => $summary['summary']['count_ok'],
          failed_count      => $summary['summary']['count_fail'],
          unknown_count     => $summary['summary']['count_unknown'],
          compliant_percent => $summary['summary']['percent_ok'],
          failed_percent    => $summary['summary']['percent_fail'],
          unknown_percent   => $summary['summary']['percent_unknown'],
        }),
        owner   => 'root',
        group   => 'root',
        mode    => '0644',
      }
    }
  }

  $reboot_classes = $rules.filter |$name, $data| {has_key($data, 'reboot') and $data['reboot'] == true }

  $classes = $reboot_classes.map |$key, $value| {
    capitalize($value['class'].split('::')).join('::')
  }

  if($reports == 'both' or $reports == 'details') {
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

  if($reboot) {
    reboot { 'after_run':
      timeout   => $reboot_timeout,
      message   => 'forced reboot by Puppet',
      subscribe => Class[$classes],
      apply     => 'finished',
    }
  }
}
