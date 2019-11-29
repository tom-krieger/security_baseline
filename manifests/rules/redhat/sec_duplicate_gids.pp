# @summary 
#    Ensure no duplicate GIDs exist (Scored)
#
# Although the groupadd program will not let you create a duplicate Group ID (GID), it is possible for an 
# administrator to manually edit the /etc/group file and change the GID field.
#
# Rationale:
# User groups must be assigned unique GIDs for accountability and to ensure appropriate access protections.
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
#   class security_baseline::rules::redhat::sec_duplicate_gids {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_duplicate_gids (
  $enforce          = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['duplicate_gids'] != 'none') {
      echo { 'duplicate-gids':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
