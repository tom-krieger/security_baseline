# @summary 
#    Ensure nftables rules are permanent (Scored)
#
# nftables is a subsystem of the Linux kernel providing filtering and classification of 
# network packets/datagrams/frames.
# The nftables service reads the /etc/sysconfig/nftables.conf file for a nftables file or 
# files to include in the nftables ruleset.
# A nftables ruleset containing the input, forward, and output base chains allow network 
# traffic to be filtered.
#
# Rationale:
# Changes made to nftables ruleset only affect the live system, you will also need to 
# configure the nftables ruleset to apply on boot.
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
#   class security_baseline::rules::redhat::sec_nftables_persistence {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_nftables_persistence (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if($enforce) {
    if(!defined(File['/etc/sysconfig/nftables.conf'])) {
      file {'/etc/sysconfig/nftable.conf':
        ensure => present,
        owner  => 'root',
        group  => 'root',
        mode   => '0644',
      }
    }
    file_line { 'add persistence file include':
      path               => '/etc/sysconfig/nftables.conf',
      line               => 'include "/etc/nftables/nftables.rules"',
      match              => 'include "/etc/nftables/nftables.rules"',
      append_on_no_match => true,
    }

    exec { 'dump nftables ruleset':
      command     => 'nft list ruleset > /etc/nftables/nftables.rules',
      path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      refreshonly => true,
    }
  }
}
