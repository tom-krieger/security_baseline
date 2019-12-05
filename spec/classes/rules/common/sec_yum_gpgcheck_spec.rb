require 'spec_helper'

describe 'security_baseline::rules::common::sec_yum_gpgcheck' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'yum_gpgcheck' => false,
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
