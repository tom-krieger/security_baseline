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
  Boolean $debug = false, # TODO: These should be aligned
  Boolean $log_info = false,
){
  if($debug) {
    # What is the purpose of this notify resource? The only thing that it
    # outputs is the version which doesn't seem all that useful. Plus it's a
    # resource which means that the run will come back with a "corrective
    # change" every run
    notify{"Applying security baseline version: ${baseline_version}": }
  }

  if ($log_info) {
    # info() is a function, meaning that it is evaluated on the Puppet master,
    # meaning that this will end up in the master's logs and not the agent's
    # logs. Since the master isn't actually applying  the securty baseline,
    # just compiling the catalog that will apply it, I would say it's not a
    # very useful log message, possibly also a bit misleading
    info("Applying security baseline version: ${baseline_version}")
  }

  # This is redundant, the Hash data types implies validation
  validate_hash($rules)

  # Try replacing this with native Puppet code, as an exercise:
  # https://puppet.com/docs/puppet/5.3/lang_resources_advanced.html#implementing-the-createresources-function
  create_resources('::security_baseline::sec_check', $rules)
}
