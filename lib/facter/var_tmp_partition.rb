# frozen_string_literal: true

# var_tmp_partition.rb
# Makes sure that /var/tmp is mounted

Facter.add('var_tmp_partition') do
  confine :kernel => 'Linux'
  setcode 'mount | grep /var/tmp'
end