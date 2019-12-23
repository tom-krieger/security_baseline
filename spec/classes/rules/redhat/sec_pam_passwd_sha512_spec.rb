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
          operatingsystemrelease: '7',
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
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          operatingsystemrelease: '8',
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
        if enforce
          is_expected.to contain_exec('update authselect config for sha512')
            .with(
              'command' => '/usr/share/security_baseline/bin/update_pam_pw_hash_sha512_config.sh',
              'path'    => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            )
          is_expected.not_to contain_echo('password-sha512')
        else
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
