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
# @example
#   include security_baseline
class security_baseline (
  String $baseline_version,
  Hash $rules,
  Boolean $debug = false,
  Boolean $log_info = false,
  String $logfile = '/tmp/security_baseline.json'
){
  if($debug) {
    notify{"Applying security baseline version: ${baseline_version}": }
  }

  if ($log_info) {
    info("Applying security baseline version: ${baseline_version}")
  }

  validate_hash($rules)

  $timestamp = generate("/bin/date +%Y-%m-%d_%H:%M:%S'")

  concat { $logfile:
    ensure => present,
    owner  => 'root',
    group  => 'root',
    mode   => '0600',
  }

  concat::fragment { 'start':
    content => epp('security_baseline/logfile_start.epp', {'time' => $timestamp}),
    target  => $logfile,
    order   => 1,
  }

  create_resources('::security_baseline::sec_check', $rules)

  $finished = generate("/bin/date +%Y-%m-%d_%H:%M:%S'")

  concat::fragment { 'finish':
    content => epp('security_baseline/logfile_end.epp', {'finish' => $finished}),
    target  => $logfile,
    order   => 9999,
  }
}
