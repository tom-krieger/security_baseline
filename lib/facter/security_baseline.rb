# frozen_string_literal: true

require 'facter/security_baseline/redhat/security_baseline_redhat'
require 'facter/security_baseline/debian/security_baseline_debian'
require 'facter/security_baseline/ubuntu/security_baseline_ubuntu'
require 'facter/security_baseline/sles/security_baseline_sles'
require 'facter/security_baseline/windows/security_baseline_windows'

Facter.add(:security_baseline) do
  osfamily = Facter.value(:osfamily).downcase
  osystem = Facter.value(:operatingsystem).downcase
  distid = Facter.value(:lsbdistid)
  release = Facter.value(:operatingsystemmajrelease)
  ret = {}
  setcode do
    case osfamily
    when 'redhat'
      ret = security_baseline_redhat(osfamily, distid, release)
    when 'debian'
      ret = if osystem == 'ubuntu'
              security_baseline_ubuntu(osfamily, distid, release)
            else
              security_baseline_debian(osfamily, distid, release)
            end
    when 'suse'
      ret = security_baseline_sles(osfamily, distid, release)
    when 'windows'
      ret = security_baseline_windows(osfamily, distid, release)
    end
  end

  ret
end
