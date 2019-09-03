require 'spec_helper'

describe 'security_baseline::rules::sec_network_tcp_syn_cookies' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'net.ipv4.tcp_syncookies' => 0,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'sctp configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
