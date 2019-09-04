require 'spec_helper'

describe 'security_baseline::rules::sec_grub2' do
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
          'message' => 'grub2',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
