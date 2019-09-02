# frozen_string_literal: true

# udf.rb
# Check if udf module is present

Facter.add('kmod_udf') do
  confine :kernel => 'Linux'
  setcode do
    check_kernel_module('udf')
  end
end
