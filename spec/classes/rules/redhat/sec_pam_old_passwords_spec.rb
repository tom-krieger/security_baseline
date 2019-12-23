require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_pam_old_passwords' do
  enforce_options.each do |enforce|
    context "RedHat 7 pam_old_passwords with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          operatingsystemrelease: '7',
          security_baseline: {
            pam: {
              opasswd: {
                status: false,
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'pam old passwords',
          'log_level' => 'warning',
          'oldpasswords' => 5,
          'sha512' => true,
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_pam('pam-system-auth-sufficient')
            .with(
              'ensure'    => 'present',
              'service'   => 'system-auth',
              'type'      => 'password',
              'control'   => 'sufficient',
              'module'    => 'pam_unix.so',
              'arguments' => ['remember=5', 'shadow', 'sha512', 'try_first_pass', 'use_authtok'],
              'position'  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
            )

          is_expected.to contain_pam('pam-password-auth-sufficient')
            .with(
              'ensure'    => 'present',
              'service'   => 'password-auth',
              'type'      => 'password',
              'control'   => 'sufficient',
              'module'    => 'pam_unix.so',
              'arguments' => ['remember=5', 'shadow', 'sha512', 'try_first_pass', 'use_authtok'],
              'position'  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
            )
          is_expected.not_to contain_echo('password-reuse')
        else
          is_expected.not_to contain_pam('pam-system-auth-sufficient')
          is_expected.not_to contain_pam('pam-password-auth-sufficient')
          is_expected.to contain_echo('password-reuse')
            .with(
              'message'  => 'pam old passwords',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end

    context "RedHat 7 without sha512 with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          operatingsystemrelease: '7',
          security_baseline: {
            pam: {
              opasswd: {
                status: false,
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'pam old passwords',
          'log_level' => 'warning',
          'oldpasswords' => 5,
          'sha512' => false,
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_pam('pam-system-auth-sufficient')
            .with(
              'ensure'    => 'present',
              'service'   => 'system-auth',
              'type'      => 'password',
              'control'   => 'sufficient',
              'module'    => 'pam_unix.so',
              'arguments' => ['remember=5', 'shadow', 'try_first_pass', 'use_authtok'],
              'position'  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
            )

          is_expected.to contain_pam('pam-password-auth-sufficient')
            .with(
              'ensure'    => 'present',
              'service'   => 'password-auth',
              'type'      => 'password',
              'control'   => 'sufficient',
              'module'    => 'pam_unix.so',
              'arguments' => ['remember=5', 'shadow', 'try_first_pass', 'use_authtok'],
              'position'  => 'after *[type="password" and module="pam_unix.so" and control="requisite"]',
            )
          is_expected.not_to contain_echo('password-reuse')
        else
          is_expected.not_to contain_pam('pam-system-auth-sufficient')
          is_expected.not_to contain_pam('pam-password-auth-sufficient')
          is_expected.to contain_echo('password-reuse')
            .with(
              'message'  => 'pam old passwords',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end

    context "RedHat 8 with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          operatingsystemrelease: '8',
          security_baseline: {
            pam: {
              opasswd: {
                status: false,
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'pam old passwords',
          'log_level' => 'warning',
          'oldpasswords' => 5,
          'sha512' => false,
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_exec('update authselect config for old passwords')
            .with(
              'command' => '/usr/share/security_baseline/bin/update_pam_pw_reuse_config.sh 5',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )
          is_expected.not_to contain_echo('password-reuse')
        else
          is_expected.not_to contain_exec('update authselect config for old passwords')
          is_expected.to contain_echo('password-reuse')
            .with(
              'message'  => 'pam old passwords',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end

        is_expected.not_to contain_pam('pam-system-auth-sufficient')
        is_expected.not_to contain_pam('pam-password-auth-sufficient')
      end
    end
  end
end
