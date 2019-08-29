require 'spec_helper'

describe 'security_baseline::rules::sec_selinux_state' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'selinux_config_mode' => 'disabled',
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'selinux',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
