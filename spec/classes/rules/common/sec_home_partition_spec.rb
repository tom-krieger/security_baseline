require 'spec_helper'

describe 'security_baseline::rules::common::sec_home_partition' do
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
              },
            },
          },
        )
      end
      let(:params) do
        {
          'enforce' => true,
          'message' => 'home partition',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('home-partition')
          .with(
            'message'  => 'home partition',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
