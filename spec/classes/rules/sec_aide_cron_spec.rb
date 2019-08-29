require 'spec_helper'

describe 'security_baseline::rules::sec_aide_cron' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'aide_cron' => '',
          'aide_version' => '',
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'aide cron',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
