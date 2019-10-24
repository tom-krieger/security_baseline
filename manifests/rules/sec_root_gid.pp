# @summary 
#    Ensure default group for the root account is GID 0 (Scored)
#
# The usermod command can be used to specify which group the root user belongs to. This affects permissions 
# of files that are created by the root user.
# 
# Rationale:
# Using GID 0 for the root account helps prevent root -owned files from accidentally becoming accessible 
# to non-privileged users.
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
# @param max_pass_days
#    Password expires after days
#
# @example
#   class security_baseline::rules::sec_root_gid {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::sec_root_gid (
  Boolean $enforce            = true,
  String $message             = '',
  String $log_level           = '',
) {
  if($enforce) {
    user { 'root':
      ensure => present,
      gid    => '0',
    }
  } else {
    if($facts['security_baseline']['accounts']['root_gid'] != 0) {
      echo { 'root-gid':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
