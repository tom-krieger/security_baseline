require 'spec_helper'

describe 'security_baseline::rules::common::sec_network_bogus_icmp_responses' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'network_parameters' => {
            'net.ipv4.icmp_ignore_bogus_error_responses' => '1',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'bogus icmp response configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
