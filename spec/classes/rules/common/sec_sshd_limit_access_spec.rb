require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_sshd_limit_access' do
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
                'allowusers' => [],
                'allowgroups' => [],
                'denyusers' => [],
                'denygroups' => [],
                'logingracetime' => 90,
                'loglevel' => 'WARN',
                'macs' => ['hmm'],
                'maxauthtries' => 5,
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
            'message' => 'sshd limit access',
            'log_level' => 'warning',
            'allow_users' => ['test1'],
            'allow_groups' => ['test1'],
            'deny_users' => ['test2'],
            'deny_groups' => ['test2'],
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_file_line('ssh-allow-users')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/ssh/sshd_config',
                'line'   => 'AllowUsers test1',
                'match'  => '^#?AllowUsers',
              )
              .that_notifies('Exec[reload-sshd]')

            is_expected.to contain_file_line('ssh-allow-groups')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/ssh/sshd_config',
                'line'   => 'AllowGroups test1',
                'match'  => '^#?AllowGroups',
              )
              .that_notifies('Exec[reload-sshd]')

            is_expected.to contain_file_line('ssh-deny-users')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/ssh/sshd_config',
                'line'   => 'DenyUsers test2',
                'match'  => '^#?DenyUsers',
              )
              .that_notifies('Exec[reload-sshd]')

            is_expected.to contain_file_line('ssh-deny-groups')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/ssh/sshd_config',
                'line'   => 'DenyGroups test2',
                'match'  => '^#?DenyGroups',
              )
              .that_notifies('Exec[reload-sshd]')

            is_expected.not_to contain_echo('sshd-limit-access')
          else
            is_expected.not_to contain_file_line('ssh-allow-users')
            is_expected.not_to contain_file_line('ssh-allow-groups')
            is_expected.not_to contain_file_line('ssh-deny-users')
            is_expected.not_to contain_file_line('ssh-deny-groups')
            is_expected.to contain_echo('sshd-limit-access')
              .with(
                'message'  => 'sshd limit access',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
