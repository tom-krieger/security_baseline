require 'spec_helper'

describe 'security_baseline::rules::debian::sec_apt_gpgcheck' do
  context 'on Debian' do
    let(:facts) do
      {
        osfamily: 'Debian',
        operatingsystem: 'Ubuntu',
        architecture: 'x86_64',
        security_baseline: {
          apt: {
            gpgcheck: false,
          },
        },
      }
    end
    let(:params) do
      {
        'enforce' => true,
        'message' => 'apt gpgcheck option',
        'log_level' => 'warning',
      }
    end

    it { is_expected.to compile }
    it do
      is_expected.to contain_echo('apt_gpgcheck')
        .with(
          'message'  => 'apt gpgcheck option',
          'loglevel' => 'warning',
          'withpath' => false,
        )
    end
  end
end
