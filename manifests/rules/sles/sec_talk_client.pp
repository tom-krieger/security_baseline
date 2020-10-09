# @summary 
#    Ensure talk client is not installed (Scored)
#
# The talk software makes it possible for users to send and receive messages across systems 
# through a terminal session. The talk client, which allows initialization of talk sessions, 
# is installed by default.
# 
# Rationale:
# The software presents a security risk as it uses unencrypted protocols for communication.
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
#   class security_baseline::rules::sles::sec_talk_client {
#       enforce => true,
#       message => 'Test',
#       log_level => 'info'
#   }
#
# @api private
class security_baseline::rules::sles::sec_talk_client (
  Boolean $enforce = true,
  String $message = '',
  String $log_level = ''
) {
  if($enforce) {
    ensure_packages(['talk'], {
      ensure => 'absent',
    })
  } else {
    if($facts['security_baseline']['packages_installed']['talk']) {
      echo { 'talk-client':
        message  => $message,
        loglevel => $log_level,
        withpath => false,
      }
    }
  }
}
