require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_hosts_deny' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'tcp_wrappers' => {
                'hosts_deny' => {
                  'status' => false,
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
            is_expected.to contain_file_line('deny all')
              .with(
                'append_on_no_match' => true,
                'match'              => 'ALL: ALL',
                'line'               => 'ALL: ALL',
                'path'               => '/etc/hosts.deny',
              )

            is_expected.not_to contain_echo('hosts-deny')
          else
            is_expected.not_to contain_file('/etc/hosts.deny')
            is_expected.to contain_echo('hosts-deny')
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
