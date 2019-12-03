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
              'scored' => true,
              'level' => 1,
              'description' => 'Support for cramfs removed',
              'enforce' => true,
              'class' => '::security_baseline::rules::redhat::sec_cramfs',
              'check' => {
                'fact_hash' => 'security_baseline',
                'fact_name' => ['kernel_modules', 'cramfs'],
                'fact_value' => false,
              },
              'message' => 'Test message unit test',
              'log_level' => 'warning,',
            },
          },
        }
      end

      it { is_expected.to compile }
    end
  end
end
