# @summary 
#    Ensure SSH X11 forwarding is disabled (Scored)
#
# The X11Forwarding parameter provides the ability to tunnel X11 traffic through the connection to enable remote 
# graphic connections.
#
# Rationale:
# Disable X11 forwarding unless there is an operational requirement to use X11 applications directly. There is a small 
# risk that the remote X11 servers of users who are logged in via SSH with X11 forwarding could be compromised by other 
# users on the X11 server. Note that even if X11 forwarding is disabled, users can always install their own forwarders.
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
#   class security_baseline::rules::sec_sshd_x11_forward {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sec_sshd_x11_forward (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($facts['security_baseline']['sshd']['package']) {
    if($enforce) {
      file_line { 'ssh-x11-forward':
        ensure => present,
        path   => '/etc/ssh/sshd_config',
        line   => 'X11Forwarding no',
        match  => '^X11Forwarding.*',
        notify => Exec['reload-sshd'],
      }
    } else {
      if($facts['security_baseline']['sshd']['x1qforward'] != 'no') {
        echo { 'sshd-x11forward':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
      }
    }
  }
}
