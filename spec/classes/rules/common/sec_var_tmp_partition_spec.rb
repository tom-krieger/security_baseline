require 'spec_helper'

describe 'security_baseline::rules::common::sec_var_tmp_partition' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'var_tmp_partition' => '/var/tmp',
          'var_tmp_nodev' => false,
          'var_tmp_noexec' => false,
          'var_tmp_nosuid' => false,
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => '/var/tmp/partition',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
