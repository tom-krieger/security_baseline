require 'spec_helper'

describe 'security_baseline::rules::common::sec_system_file_perms' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'file_permissions' => {
              'system_files_count' => 5,
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'system file permissions',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.to contain_echo('system-file-perms')
          .with(
            'message'  => 'system file permissions',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      end
    end
  end
end
