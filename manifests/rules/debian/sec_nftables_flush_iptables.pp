# @summary 
#    Ensure iptables are flushed (Not Scored)
#
# nftables is a replacement for iptables, ip6tables, ebtables and arptables
#
# Rationale:
# It is possible to mix iptables and nftables. However, this increases complexity and also the chance to introduce 
# errors. For simplicity flush out all iptables rules, and ensure it is not loaded.
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
#   class security_baseline::rules::debian::sec_nftables_flush_iptables {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#   }
#
# @api private
class security_baseline::rules::debian::sec_nftables_flush_iptables (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = '',
) {
  if ($enforce) {
    exec { 'flush iptables rules':
      command => 'iptables -F',
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => 'test $(iptables -L | grep -c -e \'^ACCEPT\' -e \'^REJECT\' -e \'^DROP\') -gt 0',
    }

    exec { 'flush ip6tables rules':
      command => 'ip6tables -F',
      path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      onlyif  => 'test $(ip6tables -L | grep -c -e \'^ACCEPT\' -e \'^REJECT\' -e \'^DROP\') -gt 0',
    }
  }
}
