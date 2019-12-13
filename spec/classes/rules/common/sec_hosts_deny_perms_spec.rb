require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_hosts_deny_perms' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'tcp_wrappers' => {
                'hosts_deny' => {
                  'status' => false,
                  'uid' => 1,
                  'gid' => 1,
                  'mode' => '777',
                  'combiined' => '1-1-777',
                },
              },
            },
            'networking' => {
              'network' => '10.10.10.0',
              'netmask' => '255.255.255.0',
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'hosts.deny',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_exec('set hosts.deny owner permissions')
              .with(
                'command' => 'chown root:root /etc/hosts.deny',
                'path'    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
              )

            is_expected.to contain_exec('set hosts.deny file permissions')
              .with(
                'command' => 'chmod 0644 /etc/hosts.deny',
                'path'    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
              )


            is_expected.not_to contain_echo('hosts-deny-perms')
          else
            is_expected.not_to contain_exec('set hosts.deny owner permissions')
            is_expected.not_to contain_exec('set hosts.deny file permissions')
            is_expected.to contain_echo('hosts-deny-perms')
              .with(
                'message'  => 'hosts.deny',
                'loglevel' => 'warning',
                'withpath' => false,
              )

          end
        end
      end
    end
  end
end
