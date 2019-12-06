require 'spec_helper'

describe 'security_baseline::rules::common::sec_gdm' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'gnome_gdm' => true,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'gdm configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
