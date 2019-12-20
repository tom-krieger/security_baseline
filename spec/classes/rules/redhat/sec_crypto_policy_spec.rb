require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_crypto_policy' do
  enforce_options.each do |enforce|
    context "RedHat with enforce = #{enforce} and policy FUTURE" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'security_baseline' => {
            'crypto_policy' => {
              'legacy' => 'LEGACY',
              'policy' => 'DEFAULT',
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'crypto policy',
          'log_level' => 'warning',
          'crypto_policy' => 'FUTURE',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_exec('set crypto policy')
            .with(
              'command' => 'update-crypto-policies --set FUTURE',
              'path'    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
            )

          is_expected.to contain_exec('set FIPS')
            .with(
              'command' => 'fips-mode-setup --disable',
              'path'    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
            )

          is_expected.not_to contain_echo('crypto-policy')
        else
          is_expected.not_to contain_exec('set crypto policy')
          is_expected.not_to contain_exec('set FIPS')
          is_expected.to contain_echo('crypto-policy')
            .with(
              'message'  => 'crypto policy',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end

    context "RedHat with enforce = #{enforce} and policy FIPS" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'security_baseline' => {
            'crypto_policy' => {
              'legacy' => 'LEGACY',
              'policy' => 'DEFAULT',
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'crypto policy',
          'log_level' => 'warning',
          'crypto_policy' => 'FIPS',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_exec('set crypto policy')
            .with(
              'command' => 'update-crypto-policies --set FIPS',
              'path'    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
            )

          is_expected.to contain_exec('set FIPS')
            .with(
              'command' => 'fips-mode-setup --enable',
              'path'    => ['/sbin', '/usr/sbin', '/bin', '/usr/bin'],
            )

          is_expected.not_to contain_echo('crypto-policy')
        else
          is_expected.not_to contain_exec('set crypto policy')
          is_expected.not_to contain_exec('set FIPS')
          is_expected.to contain_echo('crypto-policy')
            .with(
              'message'  => 'crypto policy',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
