# frozen_string_literal: true

# sctp.rb
# Check if sctp module is present

Facter.add('net_sctp') do
    confine :kernel => 'Linux'
    setcode do
      installed = Facter::Core::Execution.exec('lsmod | grep sctp')
      if installed.empty?
        false
      else
        true
      end
    end
  end
    