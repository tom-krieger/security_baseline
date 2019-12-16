require 'spec_helper'

describe 'security_baseline::rules::debian::sec_apt_gpg_keys' do
  context 'on Debian' do
    let(:facts) do
      {
        osfamily: 'Debian',
        operatingsystem: 'Ubuntu',
        architecture: 'x86_64',
        security_baseline: {
          apt_gpg_keys_config: false,
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
