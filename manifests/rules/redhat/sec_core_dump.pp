# @summary 
#    Ensure core dumps are restricted (Scored)
#
# A core dump is the memory of an executable program. It is generally used to determine why a 
# program aborted. It can also be used to glean confidential information from a core file. The 
# system provides the ability to set a soft limit for core dumps, but this can be overridden 
# by the user.
#
# Rationale:
# Setting a hard limit on core dumps prevents users from overriding the soft variable. If core dumps 
# are required, consider setting limits for user groups (see limits.conf(5) ). In addition, setting 
# the fs.suid_dumpable variable to 0 will prevent setuid programs from dumping core.
#
# @param enforce
#    Enforce the rule or just test and log
#
# @param message
#    Message to print into the log
#
# @param log_level
#    The log_level for the above message
#
# @example
#   class security_baseline::rules::redhat::sec_core_dump {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_core_dump (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {

    file_line { 'limits_hc':
      path => '/etc/security/limits.conf',
      line => '* hard core 0',
    }

    sysctl { 'fs.suid_dumpable':
      value => 0,
    }
  } else {
    if(
      ($facts['security_baseline']['coredumps'].empty) or
      ($facts['security_baseline']['sysctl']['fs.suid_dumpable'].empty) or
      ($facts['security_baseline']['sysctl']['fs.suid_dumpable'] != 0)
    ) {
      echo { 'coredumps':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
