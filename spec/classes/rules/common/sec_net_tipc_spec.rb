require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_net_tipc' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'kernel_modules' => {
                'tipc' => true,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'tipc module',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_kmod__install('tipc')
              .with(
                command: '/bin/true',
              )
            is_expected.not_to contain_echo('tipc')
          else
            is_expected.not_to contain_kmod__install('tipc')
            is_expected.to contain_echo('tipc')
              .with(
                'message'  => 'tipc module',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
