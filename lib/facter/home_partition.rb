# frozen_string_literal: true

# home_partition.rb
# Makes sure that /home is mounted

Facter.add('home_partition') do
  confine kernel: 'Linux'
  setcode 'mount | grep /home'
end
