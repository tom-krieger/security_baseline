require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_yum_gpg_keys' do
  context 'on RedHat' do
    let(:facts) do
      {
        osfamily: 'RedHat',
        operatingsystem: 'CentOS',
        architecture: 'x86_64',
        security_baseline: {
          rpm_gpg_keys_config: false,
        },
      }
    end
    let(:params) do
      {
        'enforce' => true,
        'message' => 'gpg key setup',
        'log_level' => 'warning',
      }
    end

    it {
      is_expected.to compile
      is_expected.to contain_echo('gpg-key-config')
        .with(
          'message'  => 'gpg key setup',
          'loglevel' => 'warning',
          'withpath' => false,
        )
    }
  end
end
