require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_hosts_deny' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'hosts_deny' => false,
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
            is_expected.to contain_file('/etc/hosts.deny')
              .with(
                'ensure'  => 'present',
                'owner'   => 'root',
                'group'   => 'root',
                'mode'    => '0644',
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
