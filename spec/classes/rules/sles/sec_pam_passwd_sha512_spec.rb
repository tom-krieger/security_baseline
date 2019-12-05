require 'spec_helper'

describe 'security_baseline::rules::sles::sec_pam_passwd_sha512' do
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
      }
    end

    it { is_expected.to compile }
    it do
      is_expected.to contain_pam('pam-common-sha512')
        .with(
          'ensure'    => 'present',
          'service'   => 'common-password',
          'type'      => 'password',
          'control'   => 'required',
          'module'    => 'pam_unix.so',
          'arguments' => ['sha512'],
        )
    end
  end
end
