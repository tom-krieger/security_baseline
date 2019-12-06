require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_pam_passwd_sha512' do
  context 'RedHat' do
    let(:facts) do
      {
        osfamily: 'RedHat',
        operatingsystem: 'CentOS',
        architecture: 'x86_64',
        security_baseline: {
          pam: {
            sha512: {
              status: false,
            },
          },
        },
      }
    end
    let(:params) do
      {
        'enforce' => false,
        'message' => 'pam password sha512',
        'log_level' => 'warning',
      }
    end

    it { is_expected.to compile }
    it {
      is_expected.to contain_echo('password-sha512')
        .with(
          'message'  => 'pam password sha512',
          'loglevel' => 'warning',
          'withpath' => false,
        )
    }
  end
end
