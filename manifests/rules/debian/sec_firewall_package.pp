# @summary 
#    Ensure a Firewall package is installed (Scored)
#
# A Firewall package should be selected. Most firewall configuration utilities operate 
# as a front end to nftables or iptables.
# 
# Rationale:
# A Firewall package is required for firewall management and configuration.
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
# @param firewall_package
#    The firewall package to use
#
# @example
#   class security_baseline::rules::debian::sec_firewall_package {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       firewall_package = 'iptables',
#   }
#
# @api private
class security_baseline::rules::debian::sec_firewall_package (
  Boolean $enforce                                      = true,
  String $message                                       = '',
  String $log_level                                     = '',
  Enum['iptables', 'nftables', 'ufw'] $firewall_package = 'iptables',
) {
  if($enforce) {
    case $firewall_package {
      'iptables': {
        if(!defined(Class['firewall'])) {
          class { '::firewall': }
          resources { 'firewall':
            purge => true,
          }
        }
        ensure_packages(['ufw', 'nftables'], {ensure => absent})
      }
      'ufw': {
        ensure_packages(['ufw'], {
          ensure => installed,
        })
        ensure_packages(['nftables', 'iptables'], {
          ensure => absent,
        })
      }
      'nftables': {
        ensure_packages(['nftables'], {
          ensure => installed,
        })
        ensure_packages(['ufw', 'iptables'], {
          ensure => absent,
        })
      }
      default: {
        fail("invalid firewall package selected: ${firewall_package}")
      }
    }
  } else {
    if (
      ($facts['security_baseline']['packages_installed']['ufw'] == false) and
      ($facts['security_baseline']['packages_installed']['nftables'] == false) and
      ($facts['security_baseline']['packages_installed']['iptables'] == false)
    ) {
      echo { 'firewall-package':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
