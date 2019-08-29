# frozen_string_literal: true

# tipc.rb
# Check if dctipccp module is present

Facter.add('net_tipc') do
    confine :kernel => 'Linux'
    setcode do
      installed = Facter::Core::Execution.exec('lsmod | grep tipc')
      if installed.empty?
        false
      else
        true
      end
    end
  end
    