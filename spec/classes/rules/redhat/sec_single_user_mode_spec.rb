require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_single_user_mode' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'single_user_mode_emergency' => false,
          'single_user_mode_rescue' => false,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'single user mode',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
