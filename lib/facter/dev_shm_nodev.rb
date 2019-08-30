# frozen_string_literal: true

# dev_shm_nodev.rb
# Contains the parsed values of the /dev/shm partition, looking for "nodev"

Facter.add('dev_shm_nodev') do
  confine :kernel => 'Linux'
  setcode do
    mounted = Facter::Core::Execution.exec('mount | grep /dev/shm')
    # this could be made much shorter by just returning the output of
    # "mounted.match?(%r{nodev})" as this is already returning true or false
    if mounted.match?(%r{nodev})
      true
    else
      false
    end
  end
end
