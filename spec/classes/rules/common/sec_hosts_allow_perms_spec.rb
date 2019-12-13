require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_hosts_allow_perms' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'tcp_wrappers' => {
                'hosts_allow' => {
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
            'message' => 'hosts.allow',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_exec('set hosts.allow owner permissions')
              .with(
                'command' => 'chown root:root /etc/hosts.allow',
                'path'    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
              )

            is_expected.to contain_exec('set hosts.allow file permissions')
              .with(
                'command' => 'chmod 0644 /etc/hosts.allow',
                'path'    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
              )

            is_expected.not_to contain_echo('hosts-allow-perms')
          else
            is_expected.not_to contain_exec('set hosts.allow owner permissions')
            is_expected.not_to contain_exec('set hosts.allow file permissions')
            is_expected.to contain_echo('hosts-allow-perms')
              .with(
                'message'  => 'hosts.allow',
                'loglevel' => 'warning',
                'withpath' => false,
              )

          end
        end
      end
    end
  end
end
