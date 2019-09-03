require 'spec_helper'

describe 'security_baseline::rules::sec_dev_shm_noexec' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
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
        'message' => 'dev shm noexec',
        'loglevel' => 'warning',
      }
    end

      it { is_expected.to compile }
    end
  end
end
