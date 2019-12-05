# @summary 
#    Ensure system is disabled when audit logs are full (Scored)
#
# The auditd daemon can be configured to halt the system when the audit logs are full.
#
# Rationale:
# In high security contexts, the risk of detecting unauthorized access or nonrepudiation exceeds 
# the benefit of the system's availability.
#
# @param enforce
#    Sets rule enforcemt. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param message
#    Message to print into the log
#
# @param log_level
#    Loglevel for the message
#
# @param space_left_action
#    What to do when space get low
#
# @param action_mail_acct
#    This option should contain a valid email address or alias. The default address is root. If the email address is not local to 
#    the machine, you must make sure you have email properly configured on your machine and network. Also, this option requires 
#    that /usr/lib/sendmail exists on the machine.
#
# @param admin_space_left_action
#    This parameter tells the system what action to take when the system has detected that it is low on disk space.
#
# @example
#   class { 'security_baseline::rules::common::sec_auditd_when_full':
#             enforce => true,
#             message => 'What you want to log',
#             log_level => 'warning',
#             space_left_action => 'email',
#             action_mail_acct => 'root',
#             admin_space_left_action => 'halt',
#   }
#
# @api private
class security_baseline::rules::common::sec_auditd_when_full (
  Boolean $enforce                = true,
  String $message                 = '',
  String $log_level               = '',
  String $space_left_action       = 'email',
  String $action_mail_acct        = 'root',
  String $admin_space_left_action = 'halt',
) {
  if($enforce) {
    file_line { 'auditd_space_left_action':
      line  => "space_left_action = ${space_left_action}",
      path  => '/etc/audit/auditd.conf',
      match => '^space_left_action',
    }
    file_line { 'auditd_action_mail_acct':
      line  => "action_mail_acct = ${action_mail_acct}",
      path  => '/etc/audit/auditd.conf',
      match => '^action_mail_acct',
    }
    file_line { 'auditd_admin_space_left_action':
      line  => "admin_space_left_action = ${admin_space_left_action}",
      path  => '/etc/audit/auditd.conf',
      match => '^admin_space_left_action',
    }
  } else {
    if(
      ($facts['security_baseline']['auditd']['action_mail_acct'] == 'none') or
      ($facts['security_baseline']['auditd']['admin_space_left_action'] == 'none') or
      ($facts['security_baseline']['auditd']['space_left_action'] == 'none')
    ) {
      echo { 'auditd-max-log-size':
        message  => 'Auditd setting for action_mail_acct and/or admin_space_left_action and/or space_left_action are not correct',
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
