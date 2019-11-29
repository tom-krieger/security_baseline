require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_vsftpd' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'srv_vsftpd' => 'enabled',
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'vsftpd service',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
