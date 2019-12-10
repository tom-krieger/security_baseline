require 'spec_helper'

describe 'security_baseline::rules::common::sec_world_writable_files' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'file_permissions' => {
              'world_writable_count' => 5,
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'world wriable files',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.to contain_echo('world_writable_files')
          .with(
            'message'  => 'world wriable files',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      end
    end
  end
end
