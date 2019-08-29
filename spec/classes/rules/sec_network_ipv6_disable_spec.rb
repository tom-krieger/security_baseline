require 'spec_helper'

describe 'security_baseline::rules::sec_network_ipv6_disable' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'network_parameters' => {
            'net.ipv6.conf.all.disable_ipv6' => '0',
            'net.ipv6.conf.default.disable_ipv6' => '0',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'ipv6 disable configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
