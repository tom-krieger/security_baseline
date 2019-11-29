# frozen_string_literal: true

require 'facter/security_baseline/redhat/security_baseline_redhat'
require 'facter/security_baseline/debian/security_baseline_debian'
require 'facter/security_baseline/sles/security_baseline_sles'
require 'facter/security_baseline/windows/security_baseline_windows'

Facter.add(:security_baseline) do
  os = Facter.value(:osfamily).downcase
  distid = Facter.value(:lsbdistid)
  ret = {}
  setcode do
    case os
    when 'redhat'
      ret = security_baseline_redhat(os, distid)
    when 'debian'
      ret = security_baseline_debian(os, distid)
    when 'sles'
      ret = security_baseline_sles(os, distid)
    when 'windows'
      ret = security_baseline_windows(os, distid)
    end
  end

  ret
end
