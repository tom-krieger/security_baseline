# frozen_string_literal: true

# tmp_exec.rb
# Contains the parsed values of the /tmp partition, looking for "noexec"

Facter.add('tmp_nodev') do
  confine kernel: 'Linux'
  setcode do
    mounted = Facter::Core::Execution.exec('mount | grep /tmp')
    if mounted.match?(%r{noexec})
      true
    else
      false
    end
  end
end
