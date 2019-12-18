require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_home_nodev' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'mountpoints' => {
              '/home' => {
                'options' => ['nodev'],
              },
            },
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
            'enforce' => enforce,
            'message' => 'home nodev',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_security_baseline__set_mount_options('/home-nodev')
            is_expected.not_to contain_echo('home-nodev')
          else
            is_expected.to contain_echo('home-nodev')
              .with(
                'message'  => 'home nodev',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
