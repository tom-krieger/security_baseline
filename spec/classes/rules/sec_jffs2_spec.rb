require 'spec_helper'

describe 'security_baseline::rules::sec_jffs2' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'enforce' => true,
          'message' => 'jffs2',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
