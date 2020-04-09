require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_pam_passwd_sha512' do
  enforce_options.each do |enforce|
    context "on RedHat 7 with enforce #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          operatingsystemmajrelease: '7',
          security_baseline: {
            pam: {
              sha512: {
                status: false,
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'pam password sha512',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it {
        unless enforce
          is_expected.to contain_echo('password-sha512')
            .with(
              'message'  => 'pam password sha512',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end

    context "on RedHat 8 with enforce #{enforce}" do
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
              sha512: {
                status: false,
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'pam password sha512',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it {
        if enforce
          is_expected.to contain_exec('update authselect config for sha512 system-auth')
            .with(
              'command' => "sed -ri 's/^\\s*(password\\s+sufficient\\s+pam_unix.so\\s+)(.*)$/\\1\\2 sha512/' /etc/authselect/custom/testprofile/system-auth",
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'unless'  => "test -z \"$(grep -E '^\\s*password\\s+sufficient\\s+pam_unix.so\\s+.*sha512\\s*.*$' /etc/authselect/custom/testprofile/system-auth)\"",
            )
            .that_notifies('Exec[authselect-apply-changes]')

          is_expected.to contain_exec('update authselect config for sha512 password-auth')
            .with(
              'command' => "sed -ri 's/^\\s*(password\\s+sufficient\\s+pam_unix.so\\s+)(.*)$/\\1\\2 sha512/' /etc/authselect/custom/testprofile/password-auth",
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              'unless'  => "test -z \"$(grep -E '^\\s*password\\s+sufficient\\s+pam_unix.so\\s+.*sha512\\s*.*$' /etc/authselect/custom/testprofile/password-auth)\"",
            )
            .that_notifies('Exec[authselect-apply-changes]')

          is_expected.not_to contain_echo('password-sha512')
        else
          is_expected.not_to contain_exec('update authselect config for sha512 system-auth')
          is_expected.not_to contain_exec('update authselect config for sha512 password-auth')
          is_expected.to contain_echo('password-sha512')
            .with(
              'message'  => 'pam password sha512',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
