require 'spec_helper'

describe 'security_baseline::rules::common::sec_home_dirs_exist' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'user_home_dirs' => 'suif',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'users without homedir',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('users-home-dirs-exist')
          .with(
            'message'  => 'users without homedir',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
