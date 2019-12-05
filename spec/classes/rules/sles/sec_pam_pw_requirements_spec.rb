require 'spec_helper'

describe 'security_baseline::rules::sles::sec_pam_pw_requirements' do
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
        'minlen' => 14,
        'dcredit' => -1,
        'ucredit' => -1,
        'lcredit' => -1,
        'ocredit' => -1,
      }
    end

    it { is_expected.to compile }
    it do
      is_expected.to contain_file_line('pam minlen')
        .with(
          'ensure' => 'present',
          'path'   => '/etc/security/pwquality.conf',
          'line'   => "minlen = 14",
          'match'  => '^#?minlen',
        )

      is_expected.to contain_file_line('pam dcredit')
        .with(
          'ensure' => 'present',
          'path'   => '/etc/security/pwquality.conf',
          'line'   => "dcredit = -1",
          'match'  => '^#?dcredit',
        )

      is_expected.to contain_file_line('pam ucredit')
        .with(
          'ensure' => 'present',
          'path'   => '/etc/security/pwquality.conf',
          'line'   => "ucredit = -1",
          'match'  => '^#?ucredit',
        )

      is_expected.to contain_file_line('pam ocredit')
        .with(
          'ensure' => 'present',
          'path'   => '/etc/security/pwquality.conf',
          'line'   => "ocredit = -1",
          'match'  => '^#?ocredit',
        )

      is_expected.to contain_file_line('pam lcredit')
        .with(
          'ensure' => 'present',
          'path'   => '/etc/security/pwquality.conf',
          'line'   => "lcredit = -1",
          'match'  => '^#?lcredit',
        )

      is_expected.to contain_pam('pam_cracklib common-password')
        .with(
          'ensure'    => 'present',
          'service'   => 'common-password',
          'type'      => 'password',
          'control'   => 'requisite',
          'module'    => 'pam_cracklib.so',
          'arguments' => [
            'try_first_pass',
            'retry=3',
            "minlen=14",
            "dcredit=-1",
            "ucredit=-1",
            "ocredit=-1",
            "lcredit=-1"
          ]
        )
    end
  end
end
