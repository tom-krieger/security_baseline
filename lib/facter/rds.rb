# frozen_string_literal: true

# rds.rb
# Check if rds module is present

Facter.add('net_rds') do
    confine :kernel => 'Linux'
    setcode do
      installed = Facter::Core::Execution.exec('lsmod | grep rds')
      if installed.empty?
        false
      else
        true
      end
    end
  end
    