require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_cramfs' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'kernel_modules' => {
                'cramfs' => true,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'cramfs module',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_kmod__install('cramfs')
              .with(
                command: '/bin/true',
              )
            is_expected.not_to contain_echo('cramfs')
          else
            is_expected.not_to contain_kmod__install('cramfs')
            is_expected.to contain_echo('cramfs')
              .with(
                'message'  => 'cramfs module',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
