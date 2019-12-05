require 'spec_helper'

describe 'security_baseline::rules::common::sec_iptables' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'tptables_pkg' => false,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'iptables package',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
