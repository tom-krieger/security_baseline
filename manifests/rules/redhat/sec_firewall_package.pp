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
#   class security_baseline::rules::redhat::sec_firewall_package {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       firewall_package = 'iptables',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_firewall_package (
  Boolean $enforce                                            = true,
  String $message                                             = '',
  String $log_level                                           = '',
  Enum['iptables', 'nftables', 'firewalld'] $firewall_package = 'iptables',
) {
  if($enforce) {
    if (
      ($facts['security_baseline']['packages_installed']['firewalld'] == false) and
      ($facts['security_baseline']['packages_installed']['nftables'] == false) and
      ($facts['security_baseline']['packages_installed']['iptables'] == false)
    ) {
      if($firewall_package == 'iptables') {
        if(!defined(Class['firewall'])) {
          class { '::firewall': }
        }

        resources { 'firewall':
          purge => true,
        }
      } elsif(!defined(Package[$firewall_package])) {
        package { $firewall_package:
          ensure => installed,
        }
      }
    }
  } else {
    if (
      ($facts['security_baseline']['packages_installed']['firewalld'] == false) and
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
