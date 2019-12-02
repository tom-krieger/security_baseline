require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_network_log_suspicious_packets' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'network_parameters' => {
            'net.ipv4.conf.all.log_martians' => '0',
            'net.ipv4.conf.default.log_martians' => '0',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'log suspicious packets configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
