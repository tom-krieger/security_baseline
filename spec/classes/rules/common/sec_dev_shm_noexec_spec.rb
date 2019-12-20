require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_dev_shm_noexec' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'mountpoints' => {
              '/dev/shm' => {
                'options' => ['rw'],
              },
            },
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
            'message' => 'dev shm noexec',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file_line('add /dev/shm to fstab')
              .with(
                'ensure'             => 'present',
                'append_on_no_match' => true,
                'path'               => '/etc/fstab',
                'match'              => 'tmpfs\s*on\s*/dev/shm\s*type\s*tmpfs',
                'line'               => 'tmpfs        /dev/shm        tmpfs        defaults,nodev,nosuid,noexec        0 0',
              )

            is_expected.to contain_security_baseline__set_mount_options('/dev/shm-noexec')
              .with(
                'mountpoint'   => '/dev/shm',
                'mountoptions' => 'noexec',
              )

            is_expected.not_to contain_echo('dev-shm-noexec')
          else
            is_expected.not_to contain_file_line('add /dev/shm to fstab')
            is_expected.not_to contain_security_baseline__set_mount_options('/dev/shm-noexec')
            is_expected.to contain_echo('dev-shm-noexec')
              .with(
                'message'  => 'dev shm noexec',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
