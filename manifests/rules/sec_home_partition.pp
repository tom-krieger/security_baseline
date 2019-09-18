# @summary 
#    Ensure separate partition exists for /home (Scored)
#
# The /home directory is used to support disk storage needs of local users. 
#
# Rationale:
# If the system is intended to support local users, create a separate partition for the /home directory 
# to protect against resource exhaustion and restrict the type of files that can be stored under /home.
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
#   class security_baseline::rules::sec_home_partition {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_home_partition (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {

  if($enforce) {
    if $::home_partition == undef {

      echo { 'home-partition':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
        }
      }
  }

}
