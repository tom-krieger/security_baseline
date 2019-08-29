# frozen_string_literal: true

# dev_shm_exec.rb
# Contains the parsed values of the /var/tmp partition, looking for "noexec"

Facter.add('dev_shm_noedxec') do
  confine :kernel => 'Linux'
  setcode do
    mounted = Facter::Core::Execution.exec('mount | grep /dev/shm')
    if mounted.match?(%r{noexec})
      true
    else
      false
    end
  end
end
