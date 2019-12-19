require 'spec_helper'

describe 'ecurity_baseline::rules::common::sec_crypto_policy_legacy' do
  context "RedHat with enforce = #{enforce}" do
    let(:facts) do
      {
        osfamily: 'RedHat',
        operatingsystem: 'CentOS',
        architecture: 'x86_64',
        'security_baseline' => {
          'crypto_policy' => {
            'legacy' => 'LEGACY',
            'policy' => 'DEFAULT',
          },
        },
      }
    end
    let(:params) do
      {
        'enforce' => true,
        'message' => 'crypto policy legacy',
        'log_level' => 'warning',
      }
    end

    it {
      is_expected.to compile
      
      is_expected.to contain_echo('crypto-policy-legacy')
        .with(
          'message'  => 'crypto policy legacy',
          'loglevel' => 'warning',
          'withpath' => false,
        )
    }
  end
end
