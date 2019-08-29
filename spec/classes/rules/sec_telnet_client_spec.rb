require 'spec_helper'

describe 'security_baseline::rules::sec_telnet_client' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'telnet_pkg' => true,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'telnet client package',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
