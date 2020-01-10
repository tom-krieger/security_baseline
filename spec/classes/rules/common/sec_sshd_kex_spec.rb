require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_sshd_kex' do
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
                'macs' => ['hmac-sha2-512'],
                'maxauthtries' => 5,
                'permitrootlogin' => 'yes',
                'clientaliveinterval' => 400,
                'clientalivecountmax' => 3,
                'permituserenvironment' => 'yes',
                'kexalgorithms' => ['curve25519-sha256'],
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'sshd kexs',
            'log_level' => 'warning',
            'kexs' => ['curve25519-sha256', 'ecdh-sha2-nistp256'],
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file_line('sshd-kexs')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/ssh/sshd_config',
                'line'   => 'Kexalgorithms curve25519-sha256,ecdh-sha2-nistp256',
                'match'  => '^Kexalgorithms.*',
              )
              .that_notifies('Exec[reload-sshd]')

            is_expected.not_to contain_echo('sshd-kexs-ecdh-sha2-nistp256')
          else
            is_expected.not_to contain_file_line('sshd-kexs')
            is_expected.to contain_echo('sshd-kexs-ecdh-sha2-nistp256')
              .with(
                'message'  => 'sshd kexs (ecdh-sha2-nistp256)',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
