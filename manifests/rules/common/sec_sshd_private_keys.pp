# @summary 
#    Ensure permissions on SSH private host key files are configured (Scored)
#
# An SSH private key is one of two files used in SSH public key authentication. In this authentication 
# method, The possession of the private key is proof of identity. Only a private key that corresponds 
# to a public key will be able to authenticate successfully. The private keys need to be stored and 
# handled carefully, and no copies of the private key should be distributed.
#
# Rationale:
# If an unauthorized user obtains the private SSH host key file, the host could be impersonated.
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
#   class security_baseline::rules::common::sec_sshd_private_keys {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_private_keys (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    $facts['security_baseline']['sshd']['priv_key_files'].each |$file, $data| {
      if(!defined(File[$file])) {
        file { $file:
          owner => 'root',
          group => 'root',
          mode  => '0600',
        }
      }
    }
  } else {
    if ($facts['security_baseline']['sshd']['priv_key_files_status'] == false) {
      echo { 'sshd-priv-keys':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
