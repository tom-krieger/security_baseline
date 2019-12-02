require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_kernel_aslr' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'kernel_aslr' => 1,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'kernel aslr',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
