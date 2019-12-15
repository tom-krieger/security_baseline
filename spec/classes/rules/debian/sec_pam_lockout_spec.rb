require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_pam_lockout' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            pam: {
              pwquality: {
                lockout: false,
              },
            },
          },
        }
      end
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
          is_expected.to contain_pam('pam_tally2 auth common-auth')
            .with(
              'ensure'    => 'present',
              'service'   => 'common-auth',
              'type'      => 'auth',
              'module'    => 'pam_tally2.so',
              'control'   => 'required',
              'arguments' => [
                'onerr=fail',
                'audit',
                'silent',
                'deny=3',
                'unlock_time=900',
              ],
            )

          is_expected.to contain_pam('pam_tally2 auth common-account')
            .with(
              'ensure'  => 'present',
              'service' => 'common-account',
              'type'    => 'account',
              'control' => 'required',
              'module'  => 'pam_tally2.so',
            )

          is_expected.not_to contain_echo('pam-lockout')
        else
          is_expected.not_to contain_pam('pam_tally2 auth common-auth')
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
