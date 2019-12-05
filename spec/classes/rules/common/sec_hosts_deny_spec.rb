require 'spec_helper'

describe 'security_baseline::rules::common::sec_hosts_deny' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'hosts_deny' => false,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'hosts.deny service',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
