# frozen_string_literal: true

# dev_shm_nosuid.rb
# Contains the parsed values of the /dev/shm partition, looking for "nosuid"

Facter.add('dev_shm_nosuid') do
  confine :kernel => 'Linux'
  setcode do
    mounted = Facter::Core::Execution.exec('mount | grep /dev/shm')
    mounted.match?(%r{nosuid})
  end
end