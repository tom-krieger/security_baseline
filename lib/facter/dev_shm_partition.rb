# frozen_string_literal: true

# dev_shm_partition.rb
# Makes sure that /dev/shm is mounted

Facter.add('dev_shm_partition') do
  confine :kernel => 'Linux'
  setcode 'mount | grep /dev/shm'
end