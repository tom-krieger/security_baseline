require 'spec_helper'

describe 'security_baseline::rules::sles::sec_pam_lockout' do
  context 'Suse' do
    let(:facts) { {
      :osfamily => 'Suse',
      :operatingsystem => 'SLES',
      :architecture => 'x86_64',
    } }
    let(:params) do
      {
        'enforce' => true,
        'message' => 'service chargen',
        'loglevel' => 'warning',
        'lockouttime' => 900,
        'attempts' => 3
      }
    end

    it { is_expected.to compile }
    it do
      is_expected.to contain_pam('pam_tally2 auth common-auth')
        .with(
          'ensure'    => 'present',
          'service'   => 'common-auth',
          'type'      => 'auth',
          'module'    => 'pam_tally2.so',
          'control'   => 'required',
          'arguments' => [
            'onerr=fail',
            'audit',
            'silent',
            "deny=3",
            "unlock_time=900",
          ],
        )

      is_expected.to contain_pam('pam_tally2 auth common-account')
        .with(
          'ensure'  => 'present',
          'service' => 'common-account',
          'type'    => 'account',
          'control' => 'required',
          'module'  => 'pam_tally2.so',
        )
    end
  end
end
