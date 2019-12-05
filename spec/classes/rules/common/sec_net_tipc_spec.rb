require 'spec_helper'

describe 'security_baseline::rules::common::sec_net_tipc' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'net_tipc' => true,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'tipc configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
