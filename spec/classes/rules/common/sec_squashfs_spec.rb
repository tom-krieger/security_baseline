require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_squashfs' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'kernel_modules' => {
                'squashfs' => true,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'squashfs module',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_kmod__install('squashfs')
              .with(
                command: '/bin/true',
              )
            is_expected.not_to contain_echo('squashfs')
          else
            is_expected.not_to contain_kmod__install('squashfs')
            is_expected.to contain_echo('squashfs')
              .with(
                'message'  => 'squashfs module',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
