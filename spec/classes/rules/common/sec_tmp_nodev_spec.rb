require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_tmp_nodev' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'mountpoints' => {
              '/tmp' => {
                'options' => ['rw'],
              },
            },
            'security_baseline' => {
              'partitions' => {
                'tmp' => {
                  'nodev' => false,
                  'noexec' => false,
                  'nosuid' => false,
                  'partition' => '/tmp',
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'tmp nodev',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_security_baseline__set_mount_options('/tmp-nodev')
              .with(
                'mountpoint'   => '/tmp',
                'mountoptions' => 'nodev',
              )

            is_expected.not_to contain_echo('tmp-nodev')
          else
            is_expected.not_to contain_security_baseline__set_mount_options('/tmp-nodev')
            is_expected.to contain_echo('tmp-nodev')
              .with(
                'message'  => 'tmp nodev',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
