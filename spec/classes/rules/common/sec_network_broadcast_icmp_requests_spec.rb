require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_network_broadcast_icmp_requests' do
  enforce_options.each do |enforce|
    on_supported_os.each do |os, os_facts|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'sysctl' => {
                'net.ipv4.icmp_echo_ignore_broadcasts' => 0,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'broadcast icmp requests configuration',
            'log_level' => 'warning',
          }
        end

        it { is_expected.to compile }
        it do
          if enforce
            is_expected.to contain_sysctl('net.ipv4.icmp_echo_ignore_broadcasts')
              .with(
                'value' => 1,
              )

            is_expected.not_to contain_echo('net.ipv4.icmp_echo_ignore_broadcasts')
          else
            is_expected.not_to contain_sysctl('net.ipv4.icmp_echo_ignore_broadcasts')
            is_expected.to contain_echo('net.ipv4.icmp_echo_ignore_broadcasts')
              .with(
                'message'  => 'broadcast icmp requests configuration',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        end
      end
    end
  end
end
