require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_pam_old_passwords' do
  context 'RedHat with sha512' do
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
        'oldpasswords' => 5,
        'sha512' => true,
      }
    end

    it { is_expected.to compile }
    it do
      is_expected.to contain_pam('pam-system-auth-sufficient')
        .with(
          'ensure'    => 'present',
          'service'   => 'system-auth',
          'type'      => 'password',
          'control'   => 'sufficient',
          'module'    => 'pam_unix.so',
          'arguments' => ["remember=5", 'shadow', 'sha512', 'try_first_pass', 'use_authtok'],
          'position'  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
        )

      is_expected.to contain_pam('pam-password-auth-sufficient')
        .with(
          'ensure'    => 'present',
          'service'   => 'password-auth',
          'type'      => 'password',
          'control'   => 'sufficient',
          'module'    => 'pam_unix.so',
          'arguments' => ["remember=5", 'shadow', 'sha512', 'try_first_pass', 'use_authtok'],
          'position'  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
        )
    end
  end

  context 'RedHat without sha512' do
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
        'oldpasswords' => 5,
        'sha512' => false,
      }
    end

    it { is_expected.to compile }
    it do
      is_expected.to contain_pam('pam-system-auth-sufficient')
        .with(
          'ensure'    => 'present',
          'service'   => 'system-auth',
          'type'      => 'password',
          'control'   => 'sufficient',
          'module'    => 'pam_unix.so',
          'arguments' => ["remember=5", 'shadow', 'try_first_pass', 'use_authtok'],
          'position'  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
        )

      is_expected.to contain_pam('pam-password-auth-sufficient')
        .with(
          'ensure'    => 'present',
          'service'   => 'password-auth',
          'type'      => 'password',
          'control'   => 'sufficient',
          'module'    => 'pam_unix.so',
          'arguments' => ["remember=5", 'shadow', 'try_first_pass', 'use_authtok'],
          'position'  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
        )
    end
  end
end
