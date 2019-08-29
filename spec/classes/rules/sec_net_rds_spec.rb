require 'spec_helper'

describe 'security_baseline::rules::sec_net_rds' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'net_rds' => true,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'rds configuration',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
