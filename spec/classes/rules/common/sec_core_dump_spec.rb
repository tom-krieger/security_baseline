require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_core_dump' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'coredumps' => '',
              'sysctl' => {
                'fs.suid_dumpable' => 1,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'core dump hard core',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file_line('limits_hc')
              .with(
                'path' => '/etc/security/limits.conf',
                'line' => '* hard core 0',
              )
            is_expected.to contain_sysctl('fs.suid_dumpable').with('value' => 0)
            is_expected.not_to contain_echo('coredumps')
          else
            is_expected.not_to contain_file_line('limits_hc')
            is_expected.not_to contain_sysctl('fs.suid_dumpable')
            is_expected.to contain_echo('coredumps')
              .with(
                'message'  => 'core dump hard core',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
