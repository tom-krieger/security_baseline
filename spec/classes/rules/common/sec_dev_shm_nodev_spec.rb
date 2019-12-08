require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_dev_shm_nodev' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'partitions' => {
                'shm' => {
                  'nodev' => false,
                  'noexec' => false,
                  'nosuid' => false,
                  'partition' => '/dev/shm',
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'dev shm nodev',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_echo('dev-shm-nodev')
              .with(
                'message'  => 'dev shm nodev',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          else
            is_expected.not_to contain_echo('dev-shm-nodev')
          end
        }
      end
    end
  end
end