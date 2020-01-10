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
#   class security_baseline::rules::debian::sec_nftables_table {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info',
#       nftables_default_table => 'default',
#   }
#
# @api private
class security_baseline::rules::debian::sec_nftables_table (
  Boolean $enforce               = true,
  String $message                = '',
  String $log_level              = '',
  String $nftables_default_table = 'default',
) {
  if ($enforce) {
    if(has_key($facts['security_baseline'], 'nftables')) {
      if(!($nftables_default_table in $facts['security_baseline']['nftables']['tables'])) {
        if(!defined(Package['nftables'])) {
          package { 'nftables':
            ensure => installed,
            before => Exec["create nft table ${nftables_default_table}"],        }
        }
        exec { "create nft table ${nftables_default_table}":
          command => "nft create table ${nftables_default_table} filter",
          path    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          onlyif  => "test -z \"$(nft list ruleset | grep -E '^table ${nftables_default_table}')\"",
          notify  => Exec['dump nftables ruleset'],
        }
      }
    }
  } else {
    if(has_key($facts['security_baseline'], 'nftables')) {
      if($nftables_default_table in $facts['security_baseline']['nftables']['tables']) {
        $status = true
      } else {
        $status = false
      }
    } else {
      $status = false
    }
    if($status == false) {
      echo { 'nftables-table':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
