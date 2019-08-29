# frozen_string_literal: true

# home_nodev.rb
# Contains the parsed values of the /home partition, looking for "nodev"

Facter.add('home_nodev') do
  confine :kernel => 'Linux'
  setcode do
    mounted = Facter::Core::Execution.exec('mount | grep /home')
    if mounted.match?(%r{nodev})
      true
    else
      false
    end
  end
end
  