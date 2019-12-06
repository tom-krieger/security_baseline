require 'spec_helper'

describe 'security_baseline::rules::common::sec_network_source_route' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'network_parameters' => {
            'net.ipv4.conf.all.accept_source_route' => '1',
            'net.ipv4.conf.default.accept_source_route' => '1',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'icmp rdirect configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
