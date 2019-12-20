# @summary A short summary of the purpose of this class
#
# A description of what this class does
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
# @param nftables_default_table
#    Table to be created if none exists 
#
# @example
#   class security_baseline::rules::redhat::sec_nftables_table {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       nftables_default_table => 'default',
#   }
#
# @api private
class security_baseline::rules::redhat::sec_nftables_table (
  Boolean $enforce               = true,
  String $message                = '',
  String $log_level              = '',
  String $nftables_default_table = 'default',
) {
  if ($enforce) {
    if($facts['security_baseline']['nftables']['table_count'] == 0) {
      exec { "create nfs table ${nftables_default_table}":
        command => "nft create table inet ${nftables_default_table}",
        path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
      }
    }
  } else {
    if($facts['security_baseline']['nftables']['table_count_status'] == false) {
      echo { 'nftables-table':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
