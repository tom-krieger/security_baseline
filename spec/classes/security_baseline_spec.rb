require 'spec_helper'

describe 'security_baseline' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }
      let(:params) do
        {
          'baseline_version' => '1.0.0',
          'debug' => true,
          'log_info' => true,
          'rules' => {
            '1.1.1.1' => {
              'rulename' => 'cramfs',
              'active' => true,
              'description' => 'Support for cramfs removed',
              'enforce' => true,
              'class' => '::security_baseline::rules::sec_cramfs',
              'check' => {
                'fact_name' => 'kmod_cramfs',
                'fact_value' => false,
              },
              'message' => 'Test message unit test',
              'loglevel' => 'warning,'
            },
          },
        }
      end

      it { is_expected.to compile }
    end
  end
end
