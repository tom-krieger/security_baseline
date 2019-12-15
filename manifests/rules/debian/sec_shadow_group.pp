# @summary 
#    Ensure shadow group is empty (Scored)
#
# The shadow group allows system programs which require access the ability to read the /etc/shadow file. 
# No users should be assigned to the shadow group.
#
# Rationale:
# Any users assigned to the shadow group would be granted read access to the /etc/shadow file. If attackers 
# can gain read access to the /etc/shadow file, they can easily run a password cracking program against the 
# hashed passwords to break them. Other security information that is stored in the /etc/shadow file (such 
# as expiration) could also be useful to subvert additional user accounts.
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
#   class security_baseline::rules::common::sec_empty_passwords {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::debian::sec_shadow_group (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['shadow_group_count'] != 0) {
    echo { 'shadow-group':
      message  => $message,
      loglevel => $log_level,
      withpath => false,
    }
  }
}
