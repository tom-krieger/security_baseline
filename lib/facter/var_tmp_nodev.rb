# frozen_string_literal: true

# var_tmp_nodev.rb
# Contains the parsed values of the /var/tmp partition, looking for "nodev"

Facter.add('var_tmp_nodev') do
  confine :kernel => 'Linux'
  setcode do
    mounted = Facter::Core::Execution.exec('mount | grep /var/tmp')
    if mounted.match?(%r{nodev})
      true
    else
      false
    end
  end
end
  