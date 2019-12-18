require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_pam_passwd_sha512' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
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
          'message' => 'pam sha512',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_pam('pam-common-sha512')
            .with(
              'ensure'    => 'present',
              'service'   => 'common-password',
              'type'      => 'password',
              'control'   => '[success=1, default=ignore]',
              'module'    => 'pam_unix.so',
              'arguments' => ['obscure', 'use_authtok', 'try_first_pass', 'sha512'],
            )

          is_expected.not_to contain_echo('password-sha512')
        else
          is_expected.not_to contain_pam('pam-common-sha512')
          is_expected.to contain_echo('password-sha512')
            .with(
              'message'  => 'pam sha512',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
