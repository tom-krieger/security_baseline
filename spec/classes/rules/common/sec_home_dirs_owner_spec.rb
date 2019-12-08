require 'spec_helper'

describe 'security_baseline::rules::common::sec_home_dirs_owner' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'home_dir_owners' => 'suif',
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'users own homedir',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('home-dir-perms')
          .with(
            'message'  => 'users own homedir',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
