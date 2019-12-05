require 'spec_helper'

describe 'security_baseline::rules::sles::sec_pam_old_passwords' do
  context 'Suse' do
    let(:facts) { {
      :osfamily => 'Suse',
      :operatingsystem => 'SLES',
      :architecture => 'x86_64',
    } }
    let(:params) do
      {
        'enforce' => true,
        'message' => 'pam old passwords',
        'loglevel' => 'warning',
        'oldpasswords' => 5,
      }
    end

    it { is_expected.to compile }
    it do
      is_expected.to contain_pam('pam-common-pw-history')
        .with(
          'ensure'    => 'present',
          'service'   => 'common-password',
          'type'      => 'password',
          'control'   => 'required',
          'module'    => 'pam_pwhistory.so',
          'arguments' => ["remember=5"],
        )
    end
  end
end
