# frozen_string_literal: true

# var_partition.rb
# Makes sure that /var is mounted

Facter.add('var_partition') do
  confine :kernel => 'Linux'
  setcode 'mount | grep /var'
end