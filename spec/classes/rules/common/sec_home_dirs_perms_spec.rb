require 'spec_helper'

describe 'security_baseline::rules::common::sec_home_dirs_perms' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
            'home_dir_permissions' => 'xyz',
            'partitions' => {
              'home' => {
                'nodev' => false,
                'noexec' => false,
                'nosuid' => false,
                'partition' => '/home',
              },
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'home permissions',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('home-dir-perms')
          .with(
            'message'  => 'home permissions',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
