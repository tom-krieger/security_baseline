require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_authselect_with_faillock' do
  context 'on RedHat' do
    let(:facts) do
      {
        osfamily: 'RedHat',
        operatingsystem: 'CentOS',
        architecture: 'x86_64',
        'security_baseline' => {
          'authselect' => {
            'current_options' => ['without-nullok'],
            'faillock' => 'none',
            'faillock_global' => 'with_faillock',
            'profile' => 'test',
          },
        },
      }
    end
    let(:params) do
      {
        'enforce' => true,
        'message' => 'authselect with faillock',
        'log_level' => 'warning',
      }
    end

    it {
      is_expected.to compile
      is_expected.to contain_echo('authselect-faillock')
        .with(
          'message'  => 'authselect with faillock',
          'loglevel' => 'warning',
          'withpath' => false,
        )
    }
  end
end
