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
          operatingsystemmajrelease: '7',
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

    context "RedHat 8 with enforce = #{enforce}" do
      let(:pre_condition) do
        <<-EOF
        exec { 'authselect-apply-changes':
          command     => 'authselect apply-changes',
          path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
          refreshonly => true,
        }
        EOF
      end
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          operatingsystemmajrelease: '8',
          security_baseline: {
            authselect: {
              profile: 'testprofile',
            },
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
              'command' => "sed -ri 's/^\\s*(password\\s+(requisite|sufficient)\\s+(pam_pwquality\\.so|pam_unix\\.so)\\s+)(.*)(remember=\\S+\\s*)(.*)$/\\1\\4 remember=5 \\6/' /etc/authselect/custom/testprofile/system-auth || sed -ri 's/^\\s*(password\\s+(requisite|sufficient)\\s+(pam_pwquality\\.so|pam_unix\\.so)\\s+)(.*)$/\\1\\4 remember=5/' /etc/authselect/custom/testprofile/system-auth",
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'unless'  => "test -n '$(grep -E '^\\s*password\\s+(sufficient\\s+pam_unix|requi(red|site)\\s+pam_pwhistory).so\\s+ ([^#]+\\s+)*remember=\\S+\s*.*$' /etc/authselect/custom/testprofile/system-auth)'",
            )
            .that_notifies('Exec[authselect-apply-changes]')

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
      end
    end
  end
end
