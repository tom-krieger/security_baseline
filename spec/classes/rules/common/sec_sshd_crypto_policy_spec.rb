require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_sshd_crypto_policy' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:pre_condition) do
          <<-EOF
          exec { 'reload-sshd':
            command     => 'systemctl reload sshd',
            path        => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
            refreshonly => true,
          }
          EOF
        end
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'sshd' => {
                'package' => true,
                'banner' => 'none',
                '/etc/ssh/sshd_config' => {
                  'uid' => 1,
                  'gig' => 1,
                  'mode' => 222,
                },
                'permitemptypasswords' => 'yes',
                'protocol' => 2,
                'hostbasedauthentication' => 'yes',
                'ignorerhosts' => 'no',
                'allowusers' => 'none',
                'allowgroups' => 'none',
                'denyusers' => 'none',
                'denygroups' => 'none',
                'logingracetime' => 90,
                'loglevel' => 'WARN',
                'macs' => ['hmm'],
                'maxauthtries' => 5,
                'permitrootlogin' => 'yes',
                'clientaliveinterval' => 400,
                'clientalivecountmax' => 3,
                'permituserenvironment' => 'yes',
                'usepam' => 'no',
                'allowtcpforwarding' => 'yes',
                'maxstartups' => '90:90:90',
                'maxsessions' => '5',
                'crypto_policy' => 'nananan',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'sshd crypto policy',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file_line('sshd-crypto-policy')
              .with(
                'ensure' => 'absent',
                'path'   => '/etc/ssh/sshd_config',
                'match'  => '^\s*CRYPTO_POLICY\s*=.*',
                'match_for_absence' => true,
              )
              .that_notifies('Exec[reload-sshd]')

            is_expected.not_to contain_echo('sshd-crypto-policy')
          else
            is_expected.not_to contain_file_line('sshd-crypto-policy')
            is_expected.to contain_echo('sshd-crypto-policy')
              .with(
                'message'  => 'sshd crypto policy',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
