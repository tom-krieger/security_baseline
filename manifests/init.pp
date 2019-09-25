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
  Boolean $debug            = false,
  Boolean $log_info         = false,
  String $logfile           = '/opt/puppetlabs/facter/facts.d/security_baseline_findings.yaml',
  Boolean $set_postrun      = true,
) {
  if($debug) {
    echo{"Applying security baseline version: ${baseline_version}":
      loglevel => 'debug',
      withpath => false,
    }
  }

  class { '::security_baseline::config_puppet_agent':
    before => Concat[$logfile],
  }

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

  create_resources('::security_baseline::sec_check', $rules)

  concat::fragment { 'finish':
    content => epp('security_baseline/logfile_end.epp', {}),
    target  => $logfile,
    order   => 9999,
  }
}
