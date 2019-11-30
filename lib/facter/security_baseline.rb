# frozen_string_literal: true

require 'facter/security_baseline/redhat/security_baseline_redhat'
require 'facter/security_baseline/debian/security_baseline_debian'
require 'facter/security_baseline/sles/security_baseline_sles'
require 'facter/security_baseline/windows/security_baseline_windows'

Facter.add(:security_baseline) do
  os = Facter.value(:osfamily).downcase
  distid = Facter.value(:lsbdistid)
  release = Facter.value(:operatingsystemmajrelease)
  ret = {}
  setcode do
    case os
    when 'redhat'
      ret = security_baseline_redhat(os, distid, release)
    when 'debian'
      ret = security_baseline_debian(os, distid, release)
    when 'suse'
      ret = security_baseline_sles(os, distid, release)
    when 'windows'
      ret = security_baseline_windows(os, distid, release)
    end
  end

  ret
end
