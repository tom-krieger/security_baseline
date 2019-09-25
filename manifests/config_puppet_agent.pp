# @summary 
#    Configure puppet agent postrun_command
#
# Set a postrun_command
#
# @example
#   include security_baseline::config_puppet_agent
class security_baseline::config_puppet_agent {
  if($facts['security_baseline']['puppet_agent_postrun'] != '/usr/local/bin/puppet facts upload') {
    exec { 'set puppet agent postrun':
      command => 'puppet config --section agent set postrun_command "/usr/local/bin/puppet facts upload"',
      path    => ['/bin', '/usr/bin', '/usr/local/bin'],
    }
  }
}
