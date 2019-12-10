# @summary 
#    1.6.1.3 
#
# Configure SELinux to meet or exceed the default targeted policy, which constrains daemons and system software only.
#
# Rationale:
# Security configuration requirements vary from site to site. Some sites may mandate a policy that is 
# stricter than the default policy, which is perfectly acceptable. This item is intended to ensure that 
# at least the default recommendations are met.
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
#   class security_baseline::rules::common::sec_selinux_state {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_selinux_policy (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    if(!defined(File['/etc/selinux/config'])) {
      file { '/etc/selinux/config':
        ensure => present,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
      }
    }
    file_line { 'selinux_targeted':
      path  => '/etc/selinux/config',
      line  => 'SELINUXTYPE=targeted',
      match => '^SELINUXTYPE=',
    }
  } else {
    if(($::selinux_config_policy != 'targeted') and ($::selinux_config_policy != 'mls')) {
      echo { 'selinux':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }

    }
  }
}
