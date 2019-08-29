# frozen_string_literal: true

# tcp_warppers.rb
# Check if setroubleshoot package is installed

Facter.add('tcp_wrappers_pkg') do
  confine :osfamily => 'RedHat'
  setcode do
      val = Facter::Core::Execution.exec("rpm -q tcp_wrappers")
      if val.empty? or val =~ %r{not installed} then
        false
      else
        true
      end
  end
end
