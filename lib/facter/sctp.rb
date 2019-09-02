# frozen_string_literal: true

# sctp.rb
# Check if sctp module is present

Facter.add('net_sctp') do
    confine :kernel => 'Linux'
    setcode do
      check_kernel_module('sctp')
    end
  end
    