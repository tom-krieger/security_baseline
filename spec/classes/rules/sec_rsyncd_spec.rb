require 'spec_helper'

describe 'security_baseline::rules::sec_rsyncd' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'srv_rsyncd' => 'enabled',
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'rsyncd service',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
