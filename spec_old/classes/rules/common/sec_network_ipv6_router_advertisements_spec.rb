require 'spec_helper'

describe 'security_baseline::rules::common::sec_network_ipv6_router_advertisements' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'network_parameters' => {
            'net.ipv6.conf.all.accept_ra' => '1',
            'net.ipv6.conf.default.accept_ra' => '1',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'ipv6router advertisement configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
