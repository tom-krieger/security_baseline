require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_grub_passwd' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'grub_passwd' => false,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'grub password',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
