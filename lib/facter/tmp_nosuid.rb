# frozen_string_literal: true

# tmp_nosuid.rb
# Contains the parsed values of the /tmp partition, looking for "nodev"

Facter.add('tmp_nosuid') do
  confine kernel: 'Linux'
  setcode do
    mounted = Facter::Core::Execution.exec('mount | grep /tmp')
    if mounted.match?(%r{nosuid})
      true
    else
      false
    end
  end
end
