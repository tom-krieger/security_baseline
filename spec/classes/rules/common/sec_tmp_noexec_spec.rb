require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_tmp_noexec' do
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
            'message' => 'tmp noexec',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_security_baseline__set_mount_options('/tmp-noexec')
              .with(
                'mountpoint'   => '/tmp',
                'mountoptions' => 'noexec',
              )

            is_expected.not_to contain_echo('tmp-noexec')
          else
            is_expected.not_to contain_security_baseline__set_mount_options('/tmp-noexec')
            is_expected.to contain_echo('tmp-noexec')
              .with(
                'message'  => 'tmp noexec',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
