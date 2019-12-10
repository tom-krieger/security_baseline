require 'spec_helper'

describe 'security_baseline::rules::common::sec_users_netrc_files_write' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it { is_expected.to compile }
    end
  end
end
describe 'security_baseline::rules::common::sec_users_dot_files' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'user_dot_file_write' => 'test1',
            'forward_files' => 'test1',
            'netrc_files_write' => 'test1',
            'netrc_files' => 'test1',
            'rhosts_files' => 'test1',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'user dnetrcot files',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.to contain_echo('user-netrc-files-write')
          .with(
            'message'  => 'user netrc files',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      end
    end
  end
end
