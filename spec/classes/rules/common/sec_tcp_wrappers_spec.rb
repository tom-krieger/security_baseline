require 'spec_helper'

describe 'security_baseline::rules::common::sec_tcp_wrappers' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'tcp_warppers_pkg' => false,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'tcp_wrappers install',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
