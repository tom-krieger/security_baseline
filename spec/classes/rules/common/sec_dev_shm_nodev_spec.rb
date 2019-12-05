require 'spec_helper'

describe 'security_baseline::rules::common::sec_dev_shm_nodev' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'dev_shm_nodev' => false,
          'dev_shm_noexec' => false,
          'dev_shm_nosuid' => false,
          'dev_shm_partition' => '/dev/shm',
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'dev shm nodev',
          'loglevel' => 'warning',
        }
      end

      it { is_expected.to compile }
    end
  end
end
