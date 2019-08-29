# frozen_string_literal: true

# var_tmp_exec.rb
# Contains the parsed values of the /var/tmp partition, looking for "noexec"

Facter.add('var_tmp_noexec') do
  confine :kernel => 'Linux'
  setcode do
    mounted = Facter::Core::Execution.exec('mount | grep /var/tmp')
    if mounted.match?(%r{noexec})
      true
    else
      false
    end
  end
end
