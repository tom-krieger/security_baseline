require 'spec_helper'

describe 'security_baseline::rules::common::sec_home_nodev' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) do
        os_facts.merge(
          'security_baseline' => {
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
          'message' => 'home nodev',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        is_expected.to contain_echo('home-nodev')
          .with(
            'message'  => 'home nodev',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      }
    end
  end
end
