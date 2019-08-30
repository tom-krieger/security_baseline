# @summary
#    Check a security rule. 
#
# Check a security rule, enforce it or just monitor it and log into the Puppet log files.
#
# @param rulename
#    Name of the rule for loggting
#
# @param active
#    Sets a rule active or inactive. Inactive rules will not be used
#
# @param description
#    Information about the rule. Currently only for information.
#
# @param enforce
#    Sets rule enforcemt. If set to true, code will be exeuted to bring the system into a comliant state.
#
# @param class 
#    Class implementing the rule. This might be a class with this module but can reference an external class as well. 
#    This makes this module highly generic.
#
# @param check
#    A hash describing the fact for the test and the desired value
#
# @param message
#    Message to print into the log
#
# @param loglevel
#    Loglevel for the message
#
# @param config_data
#    Additional configuration data, especially if external security modules are used to provide configuration data
#    to those modules
#
# @example
#   security_baseline::sec_check { '1.1.2': 
#       rulename => 'tmp_partition',
#       active => true,
#       description => 'The /tmp directory ...',
#       enforce => true,
#       class => '::security_baseline::rules::sec_tmp_partition',
#       check => {
#         fact_name => 'tmp_partition',
#         fact_value => '/tmp',
#       },
#       message => 'Not in compliance with rule 1.1.2. No seperate directory for /tmp.',
#       loglevel => 'warning',
#   }
define security_baseline::sec_check (
  String $rulename, # TODO: Alignment
  String $description,
  Boolean $enforce,
  String $class,
  Hash $check,
  String $message = '', # TODO: Alignment
  String $loglevel = 'warning',
  Boolean $active = true,
  Optional[Hash] $config_data = {},
) {
    if($active) {

      if($::security_baseline::debug) {
        # As before, unless there is a good reason to be doing this I would not
        # use notifys
        notify{"Applying rule ${rulename}": }
      }

      # What is the idea behind all of this fact checking? Is the idea that for
      # things that you can't write enforcement code for you could use a fact
      # instead and this would just return a notify if the thing needs to be
      # fixed?
      $fact_name = $check['fact_name']
      if($fact_name != '') {

        $fact_value = $check['fact_value']
        $current_value = $facts[$fact_name]

        if($current_value != $fact_value) {
          if($::security_baseline::debug) {
            # This is a much more useful message than any of the others and
            # does legitimatey represent a scenario where the server needs
            # remediation as opposed to just an informational message, for
            # that reason I'd say it might be valid to use a notify in this
            # instance. The only problem is that all of the notifys are
            # enabled and disabled by the debug parameter meaning that you
            # can't have just the useful ones, you have to have all or nothing.
            notify{"Fact ${fact_name} should have value '${fact_value}' but has current value '${current_value}'": }
          }
          if($::security_baseline::log_info) {
            # Same note as before about info()
            info("Fact ${fact_name} should have value '${fact_value}' but has current value '${current_value}'")
          }
        }

      }

      # You don't have to do this. Experiment with "undef"
      if(empty($config_data)) {

        class { $class:
          enforce  => $enforce,
          message  => $message,
          loglevel => $loglevel,
        }

      } else {

        # The only problem that I see with this is the fact that people have to
        # rewrite all of their modules to use this because it has to use the
        # known interface. Using functionality like this:
        # https://puppet.com/docs/puppet/latest/lang_resources.html#setting-attributes-from-a-hash
        # might mean that you no longer need to have a static interface
        class { $class:
          enforce     => $enforce,
          message     => $message,
          loglevel    => $loglevel,
          config_data => $config_data,
        }
      }
    }
}
