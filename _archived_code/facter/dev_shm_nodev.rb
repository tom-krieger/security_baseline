# frozen_string_literal: true

# dev_shm_nodev.rb
# Contains the parsed values of the /dev/shm partition, looking for "nodev"

Facter.add('dev_shm_nodev') do
  confine kernel: 'Linux'
  setcode do
    mounted = Facter::Core::Execution.exec('mount | grep /dev/shm')
    mounted.match?(%r{nodev})
  end
end
