require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_journald_compress_logs' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'journald' => {
                'compress' => 'none',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'journald compress logs',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file_line('compress logs')
              .with(
                'path'  => '/etc/systemd/journald.conf',
                'match' => 'Compress=',
                'line'  => 'Compress=yes',
              )

            is_expected.not_to contain_echo('journald-compress')
          else
            is_expected.not_to contain_file_line('compress logs')
            is_expected.to contain_echo('journald-compress')
              .with(
                'message'  => 'journald compress logs',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
