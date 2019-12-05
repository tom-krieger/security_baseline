require 'spec_helper'

describe 'security_baseline::rules::common::sec_motd_permissions' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'enforce' => true,
          'message' => 'motd permissions',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
