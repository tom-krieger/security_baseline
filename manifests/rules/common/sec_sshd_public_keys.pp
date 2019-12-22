# @summary 
#    Ensure permissions on SSH public host key files are configured (Scored)
#
# An SSH public key is one of two files used in SSH public key authentication. In this authentication method, 
# a public key is a key that can be used for verifying digital signatures generated using a corresponding private 
# key. Only a public key that corresponds to a private key will be able to authenticate successfully.
#
# Rationale:
# If a public host key file is modified by an unauthorized user, the SSH service may be compromised.
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
#   class security_baseline::rules::common::sec_sshd_public_keys {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::common::sec_sshd_public_keys (
  Boolean $enforce  = true,
  String $message   = '',
  String $log_level = ''
) {
  if ($enforce) {
    $facts['security_baseline']['sshd']['pub_key_files'].each |$file, $data| {
      if(!defined(File[$file])) {
        file { $file:
          owner => 'root',
          group => 'root',
          mode  => '0644',
        }
      }
    }
  } else {
    if ($facts['security_baseline']['sshd']['pub_key_files_status'] == false) {
      echo { 'sshd-pub-keys':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
