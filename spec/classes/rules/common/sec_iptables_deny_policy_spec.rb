require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_iptables_deny_policy' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'iptables' => {
                'policy_status' => false,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'iptables default policies',
            'log_level' => 'warning',
            'input_policy' => 'drop',
            'output_policy' => 'drop',
            'forward_policy' => 'drop',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to contain_firewallchain('OUTPUT:filter:IPv4')
              .with(
                'ensure' => 'present',
                'policy' => 'drop',
              )

            is_expected.to contain_firewallchain('FORWARD:filter:IPv4')
              .with(
                'ensure' => 'present',
                'policy' => 'drop',
              )

            is_expected.to contain_firewallchain('INPUT:filter:IPv4')
              .with(
                'ensure' => 'present',
                'policy' => 'drop',
              )

            is_expected.not_to contain_echo('iptables-policy-status')
          else
            is_expected.not_to contain_firewallchain('OUTPUT:filter:IPv4')
            is_expected.not_to contain_firewallchain('FORWARD:filter:IPv4')
            is_expected.not_to contain_firewallchain('INPUT:filter:IPv4')
            is_expected.to contain_echo('iptables-policy-status')
              .with(
                'message'  => 'iptables default policies',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
