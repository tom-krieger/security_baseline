require 'spec_helper'

describe 'security_baseline::rules::common::sec_ungrouped_files' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }
    end
  end
end
describe 'security_baseline::rules::common::sec_ungrouped_files' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'file_permissions' => {
              'ungrouped_count' => 5,
              'unowned_count' => 6,
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'files without existing group',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.to contain_echo('ungrouped_files')
          .with(
            'message'  => 'files without existing group',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      end
    end
  end
end
