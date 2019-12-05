require 'spec_helper'

describe 'security_baseline::rules::common::sec_network_broadcast_icmp_requests' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'network_parameters' => {
            'net.ipv4.icmp_echo_ignore_broadcasts' => '1',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'broadcast icmp requests configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
