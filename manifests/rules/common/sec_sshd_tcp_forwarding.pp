# @summary 
#    Ensure SSH AllowTcpForwarding is disabled (Scored)
#
# SSH port forwarding is a mechanism in SSH for tunneling application ports from the client to the server, 
# or servers to clients. It can be used for adding encryption to legacy applications, going through firewalls, 
# and some system administrators and IT professionals use it for opening backdoors into the internal network 
# from their home machines
#
# Rationale:
# Leaving port forwarding enabled can expose the organization to security risks and backdoors.
# SSH connections are protected with strong encryption. This makes their contents invisible to most deployed 
#network monitoring and traffic filtering solutions. This invisibility carries considerable risk potential if 
# it is used for malicious purposes such as data exfiltration. Cybercriminals or malware could exploit SSH to 
# hide their unauthorized communications, or to exfiltrate stolen data from the target network
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
#   class security_baseline::rules::common::sec_sshd_use_pam {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_tcp_forwarding (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    file_line { 'sshd-tcp-forwarding':
      ensure             => present,
      path               => '/etc/ssh/sshd_config',
      line               => 'AllowTcpForwarding no',
      match              => '^AllowTcpForwarding.*',
      append_on_no_match => true,
      notify             => Exec['reload-sshd'],
    }
  } else {
    if($facts['security_baseline']['sshd']['allowtcpforwarding'] != 'no') {
        echo { 'sshd-tcp-forwarding':
          message  => $message,
          loglevel => $log_level,
          withpath => false,
        }
    }
  }
}
