require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_iptables_loopback' do
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
            'message' => 'loopback traffic',
            'log_level' => 'warning',
          }
        end

        it { 
          is_expected.to compile 
        
          if enforce
            is_expected.to contain_firewall('001 accept all incoming traffic to local interface')
              .with(
                'chain'   => 'INPUT',
                'proto'   => 'all',
                'iniface' => 'lo',
                'action'  => 'accept',
              )

            is_expected.to contain_firewall('002 accept all outgoing traffic to local interface')
              .with(
                'chain'    => 'OUTPUT',
                'proto'    => 'all',
                'outiface' => 'lo',
                'action'   => 'accept',
              )
              .that_requires('Firewall[001 accept all incoming traffic to local interface]')

            is_expected.to contain_firewall('003 drop all traffic to lo 127.0.0.1/8')
              .with(
                'chain'   => 'INPUT',
                'proto'   => 'all',
                'source'  => '127.0.0.1/8',
                'action'  => 'drop',
              )
              .that_requires('Firewall[002 accept all outgoing traffic to local interface]')
          else
            is_expected.not_to contain_firewall('001 accept all incoming traffic to local interface')
            is_expected.not_to contain_firewall('002 accept all outgoing traffic to local interface')
            is_expected.not_to contain_firewall('003 drop all traffic to lo 127.0.0.1/8')
          end
        }
      end
    end
  end
end
