require 'spec_helper'

describe 'security_baseline::rules::sec_network_icmp_redirect' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'network_parameters' => {
            'net.ipv4.conf.all.accept_redirects' => '1',
            'net.ipv4.conf.default.accept_redirects' => '1',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'icmp redirect packets configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
