# @summary 
#    Configure puppet agent postrun_command
#
# Set a postrun_command
#
# @example
#   include security_baseline::config_puppet_agent
class security_baseline::config_puppet_agent {

  if(('security_baseline' in $facts) and ('puppet_agent_potrun' in $facts['security_baseline'])) {
    if ($facts['security_baseline']['puppet_agent_postrun'] != 'postrun_command = /usr/local/bin/puppet facts upload') {
      exec { 'set puppet agent postrun agent':
        command => 'puppet config --section agent set postrun_command "/usr/local/bin/puppet facts upload"',
        path    => ['/bin', '/usr/bin', '/usr/local/bin'],
      }
      exec { 'set puppet agent postrun main':
        command => 'puppet config --section main set postrun_command "/usr/local/bin/puppet facts upload"',
        path    => ['/bin', '/usr/bin', '/usr/local/bin'],
      }
    }
  } else {
    exec { 'set puppet agent postrun agent':
      command => 'puppet config --section agent set postrun_command "/usr/local/bin/puppet facts upload"',
      path    => ['/bin', '/usr/bin', '/usr/local/bin'],
    }
    exec { 'set puppet agent postrun main':
      command => 'puppet config --section main set postrun_command "/usr/local/bin/puppet facts upload"',
      path    => ['/bin', '/usr/bin', '/usr/local/bin'],
    }
  }
}
