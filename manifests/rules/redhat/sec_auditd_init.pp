# @summary 
#    Initialize auditd rules file
#
# Write inital rules for auditd
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
#   class security_baseline::rules::redhat::sec_auditd_init {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       buffer_size => 8192
#   }
#
# @api private
class security_baseline::rules::redhat::sec_auditd_init (
  Boolean $enforce     = true,
  String $message      = '',
  String $log_level    = '',
  Integer $buffer_size = 8192,
) {
  if($enforce) {
    file { $security_baseline::auditd_rules_file:
      ensure => present,
      owner  => 'root',
      group  => 'root',
      mode   => '0750',
    }
    file_line {'auditd init delete rules':
      ensure  => present,
      path    => $security_baseline::auditd_rules_file,
      line    => '-D',
      require => File[$security_baseline::auditd_rules_file],
    }
    file_line {'auditd init set buffer':
      ensure  => present,
      path    => $security_baseline::auditd_rules_file,
      line    => "-b ${buffer_size}",
      require => File[$security_baseline::auditd_rules_file],
    }
  }
}
