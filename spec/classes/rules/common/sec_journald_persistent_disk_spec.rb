require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_journald_persistent_disk' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'journald' => {
                'storage_persistent' => 'none',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'journald persistent storage',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file_line('write to persistent disk')
              .with(
                'path'  => '/etc/systemd/journald.conf',
                'match' => 'Storage=',
                'line'  => 'Storage=persistent',
              )

            is_expected.not_to contain_echo('journald-storage-persistent')
          else
            is_expected.not_to contain_file_line('write to persistent disk')
            is_expected.to contain_echo('journald-storage-persistent')
              .with(
                'message'  => 'journald persistent storage',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
