require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_freevxfs' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'kernel_modules' => {
                'freevxfs' => true,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'freevxfs module',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_kmod__install('freevxfs')
              .with(
                command: '/bin/true',
              )
            is_expected.not_to contain_echo('freevxfs')
          else
            is_expected.not_to contain_kmod__install('freevxfs')
            is_expected.to contain_echo('freevxfs')
              .with(
                'message'  => 'freevxfs module',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
