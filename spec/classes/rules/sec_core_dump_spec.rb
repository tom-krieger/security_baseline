require 'spec_helper'

describe 'security_baseline::rules::sec_core_dump' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'enforce' => true,
          'message' => 'core dump hard core',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
