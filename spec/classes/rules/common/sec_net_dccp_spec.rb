require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_net_dccp' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'kernel_modules' => {
                'dccp' => true,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'dccp module',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_kmod__install('dccp')
              .with(
                command: '/bin/true',
              )
            is_expected.not_to contain_echo('dccp')
          else
            is_expected.not_to contain_kmod__install('dccp')
            is_expected.to contain_echo('dccp')
              .with(
                'message'  => 'dccp module',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
