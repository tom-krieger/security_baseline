# @summary 
#    Ensure no duplicate group names exist (Scored)
#
# Although the groupadd program will not let you create a duplicate group name, it is possible for an administrator 
# to manually edit the /etc/group file and change the group name.
#
# Rationale:
# If a group is assigned a duplicate group name, it will create and have access to files with the first GID for that 
# group in /etc/group . Effectively, the GID is shared, which is a security problem.
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
#   class security_baseline::rules::redhat::sec_duplicate_groups {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_duplicate_groups (
  $enforce          = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['duplicate_groups_count'] != 0) {
      echo { 'duplicate-groups':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
