require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_sshd_private_keys' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'sshd' => {
                'priv_key_files_status' => false,
                'priv_key_files' => {
                  '/etc/ssh/ssh_host_ecdsa_key' => {
                    'combined' => '0-997-416',
                    'gid' => '997',
                    'mode' => '416',
                    'uid' => '0',
                  },
                },
                'package' => true,
                'banner' => 'none',
                '/etc/ssh/sshd_config' => {
                  'uid' => 1,
                  'gig' => 1,
                  'mode' => 222,
                },
                'permitemptypasswords' => 'yes',
                'protocol' => '1',
                'hostbasedauthentication' => 'yes',
                'ignorerhosts' => 'no',
                'allowusers' => 'none',
                'allowgroups' => 'none',
                'denyusers' => 'none',
                'denygroups' => 'none',
                'logingracetime' => 90,
                'loglevel' => 'WARN',
                'macs' => ['hmm'],
                'maxauthtries' => '5',
                'permitrootlogin' => 'yes',
                'clientaliveinterval' => 400,
                'clientalivecountmax' => 3,
                'permituserenvironment' => 'yes',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'sshd private keys',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file('/etc/ssh/ssh_host_ecdsa_key')
              .with(
                'owner' => 'root',
                'group' => 'root',
                'mode'  => '0600',
              )

            is_expected.not_to contain_echo('sshd-priv-keys')
          else
            is_expected.not_to contain_file('/etc/ssh/ssh_host_ecdsa_key')
            is_expected.to contain_echo('sshd-priv-keys')
              .with(
                'message'  => 'sshd private keys',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
