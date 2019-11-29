# @summary 
#    Ensure no duplicate UIDs exist (Scored)
#
# Although the useradd program will not let you create a duplicate User ID (UID), it is possible for an 
# administrator to manually edit the /etc/passwd file and change the UID field.
#
# Rationale:
# Users must be assigned unique UIDs for accountability and to ensure appropriate access protections.
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
#   class security_baseline::rules::redhat::sec_duplicate_uids {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_duplicate_uids (
  $enforce          = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['duplicate_uids_count'] != 0) {
      echo { 'duplicate-uids':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
