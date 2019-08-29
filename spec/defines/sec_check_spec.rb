require 'spec_helper'

describe 'security_baseline::sec_check' do
  let(:title) { '1.1.1' }
  let(:params) do
    {
      'rulename' => 'cramfs',
      'description' => 'Support for cramfs removed',
      'enforce' => true,
      'class' => '::security_baseline::sec_cramfs',
      'check' => {
        'fact_name' => 'kmod_cramfs',
        'fact_value' => false,
      },
    }
  end

  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }
    end
  end
end
