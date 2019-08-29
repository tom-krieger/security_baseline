# frozen_string_literal: true

# var_log_partition.rb
# Makes sure that /var/log is mounted

Facter.add('var_log_partition') do
  confine :kernel => 'Linux'
  setcode 'mount | grep /var/log'
end