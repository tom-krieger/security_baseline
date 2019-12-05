require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_pam_pw_requirements' do
  context 'RedHat' do
    let(:facts) { {
      :osfamily => 'RedHat',
      :operatingsystem => 'CentOS',
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

      is_expected.to contain_pam('pam-system-auth-requisite')
        .with(
          'ensure'    => 'present',
          'service'   => 'system-auth',
          'type'      => 'password',
          'control'   => 'requisite',
          'module'    => 'pam_pwquality.so',
          'arguments' => ['try_first_pass', 'retry=3']
        )

      is_expected.to contain_pam('pam-password-auth-requisite')
        .with(
          'ensure'    => 'present',
          'service'   => 'password-auth',
          'type'      => 'password',
          'control'   => 'requisite',
          'module'    => 'pam_pwquality.so',
          'arguments' => ['try_first_pass', 'retry=3']
        )
    end
  end
end
