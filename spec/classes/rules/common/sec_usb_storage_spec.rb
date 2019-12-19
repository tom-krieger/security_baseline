require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_usb_storage' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'kernel_modules' => {
                'usb-storage' => true,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'usb-storage module',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_kmod__install('usb-storage')
              .with(
                command: '/bin/true',
              )
            is_expected.not_to contain_echo('usb-storage')
          else
            is_expected.not_to contain_kmod__install('usb-storage')
            is_expected.to contain_echo('usb-storage')
              .with(
                'message'  => 'usb-storage module',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
