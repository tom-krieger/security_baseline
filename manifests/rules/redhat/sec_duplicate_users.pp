# @summary 
#    Ensure no duplicate user names exist (Scored)
#
# Although the useradd program will not let you create a duplicate user name, it is possible for an administrator to 
# manually edit the /etc/passwd file and change the user name.
#
# Rationale:
# If a user is assigned a duplicate user name, it will create and have access to files with the first UID for that 
# username in /etc/passwd . For example, if "test4" has a UID of 1000 and a subsequent "test4" entry has a UID of 2000, 
# logging in as "test4" will use UID 1000. Effectively, the UID is shared, which is a security problem.
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
#   class security_baseline::rules::redhat::sec_duplicate_users {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::redhat::sec_duplicate_users (
  $enforce          = true,
  String $message   = '',
  String $log_level = ''
) {
  if($enforce) {

  } else {
    if ($facts['security_baseline']['duplicate_users'] != 'none') {
      echo { 'duplicate-users':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
