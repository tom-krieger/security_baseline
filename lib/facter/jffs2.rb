require 'facter/helpers/check_kernel_module'

# frozen_string_literal: true

# kmod_jffs2.rb
# Check for jffs2 kernel module

Facter.add('kmod_jffs2') do
  confine kernel: 'Linux'
  setcode do
    check_kernel_module('jffs2')
  end
end
