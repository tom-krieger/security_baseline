require 'spec_helper'

describe 'security_baseline::rules::sles::sec_zypper_gpg_keys' do
  context 'on Suse' do
    let(:facts) do
      {
        osfamily: 'Suse',
        operatingsystem: 'SLEs',
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
