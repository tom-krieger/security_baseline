require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_rhsm_identity' do
  context 'on RedHat' do
    let(:facts) do
      {
        osfamily: 'RedHat',
        operatingsystem: 'RedHat',
        architecture: 'x86_64',
      }
    end
    let(:params) do
      {
        'enforce' => true,
        'message' => 'redhat subscription manager',
        'log_level' => 'warning',
      }
    end

    it {
      is_expected.to compile
      is_expected.to contain_echo('rhsm-identity')
        .with(
          'message'  => 'redhat subscription manager',
          'loglevel' => 'warning',
          'withpath' => false,
        )
    }
  end
end
