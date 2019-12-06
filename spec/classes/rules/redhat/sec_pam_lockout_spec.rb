require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_pam_lockout' do

  enforce_options.each do |enforce|

    context "RedHat with enforce = #{enforce}" do
    
      let(:facts) { {
        :osfamily => 'RedHat',
        :operatingsystem => 'CentOS',
        :architecture => 'x86_64',
        :security_baseline => {
          :pam => {
            :pwquality => {
              :lockout => false
            }
          }
        }
      } }
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'pam lockout',
          'log_level' => 'warning',
          'lockouttime' => 900,
          'attempts' => 3,
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_pam('pam_unix system-auth')
            .with(
              'ensure'           => 'present',
              'service'          => 'system-auth',
              'type'             => 'auth',
              'module'           => 'pam_unix.so',
              'control'          => '[success=1 default=bad]',
              'control_is_param' => true,
              'arguments'        => [],
            )

          is_expected.to contain_pam('pam_faillock preauth system-auth')
            .with(
              'ensure'           => 'present',
              'service'          => 'system-auth',
              'type'             => 'auth',
              'module'           => 'pam_faillock.so',
              'control'          => 'required',
              'control_is_param' => true,
              'arguments'        => [
                'preauth',
                'audit',
                'silent',
                "deny=3",
                "unlock_time=900",
              ],
              'position'         => 'before *[type="auth" and module="pam_unix.so"]',
            )

          is_expected.to contain_pam('pam_faillock authfail system-auth')
            .with(
              'ensure'           => 'present',
              'service'          => 'system-auth',
              'type'             => 'auth',
              'module'           => 'pam_faillock.so',
              'control'          => '[default=die]',
              'control_is_param' => true,
              'arguments'        => [
                'authfail',
                'audit',
                "deny=3",
                "unlock_time=900",
              ],
              'position'         => 'after *[type="auth" and module="pam_unix.so"]',
            )

          is_expected.to contain_pam('pam_faillock authsucc system-auth')
            .with(
              'ensure'           => 'present',
              'service'          => 'system-auth',
              'type'             => 'auth',
              'module'           => 'pam_faillock.so',
              'control'          => 'sufficient',
              'control_is_param' => true,
              'arguments'        => [
                'authsucc',
                'audit',
                "deny=3",
                "unlock_time=900",
              ],
              'position'         => 'after *[type="auth" and module="pam_faillock.so" and control="[default=die]"]',
            )

          is_expected.to contain_pam('pam_unix password-auth')
            .with(
              'ensure'           => 'present',
              'service'          => 'password-auth',
              'type'             => 'auth',
              'module'           => 'pam_unix.so',
              'control'          => '[success=1 default=bad]',
              'control_is_param' => true,
              'arguments'        => [],
            )

          is_expected.to contain_pam('pam_faillock preauth password-auth')
            .with(
              'ensure'           => 'present',
              'service'          => 'password-auth',
              'type'             => 'auth',
              'module'           => 'pam_faillock.so',
              'control'          => 'required',
              'control_is_param' => true,
              'arguments'        => [
                'preauth',
                'audit',
                'silent',
                "deny=3",
                "unlock_time=900",
              ],
              'position'         => 'before *[type="auth" and module="pam_unix.so"]',
            )

          is_expected.to contain_pam('pam_faillock authfail password-auth')
            .with(
              'ensure'           => 'present',
              'service'          => 'password-auth',
              'type'             => 'auth',
              'module'           => 'pam_faillock.so',
              'control'          => '[default=die]',
              'control_is_param' => true,
              'arguments'        => [
                'authfail',
                'audit',
                "deny=3",
                "unlock_time=900",
              ],
              'position'         => 'after *[type="auth" and module="pam_unix.so"]',
            )

          is_expected.to contain_pam('pam_faillock authsucc password-auth')
            .with(
              'ensure'           => 'present',
              'service'          => 'password-auth',
              'type'             => 'auth',
              'module'           => 'pam_faillock.so',
              'control'          => 'sufficient',
              'control_is_param' => true,
              'arguments'        => [
                'authsucc',
                'audit',
                "deny=3",
                "unlock_time=900",
              ],
              'position'         => 'after *[type="auth" and module="pam_faillock.so" and control="[default=die]"]',
            )

            is_expected.not_to contain_echo('pam-lockout')
        else
          is_expected.not_to contain_pam('pam_unix system-auth')
          is_expected.not_to contain_pam('pam_faillock preauth system-auth')
          is_expected.not_to contain_pam('pam_faillock authfail system-auth')
          is_expected.not_to contain_pam('pam_faillock authsucc system-auth')
          is_expected.not_to contain_pam('pam_unix password-auth')
          is_expected.not_to contain_pam('pam_faillock preauth password-auth')
          is_expected.not_to contain_pam('pam_faillock authfail password-auth')
          is_expected.not_to contain_pam('pam_faillock authsucc password-auth')
          is_expected.to contain_echo('pam-lockout')
            .with(
              'message'  => 'pam lockout',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
