require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_selinux' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'selinux_pkg' => false,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'selinux pkg',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
