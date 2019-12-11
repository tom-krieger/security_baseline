require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_automounting' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'services_enabled' => {
                'srv_autofs' => 'enabled',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'automounting',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile

          if enforce
            is_expected.to create_class('autofs')
              .with(
                'service_ensure' => 'stopped',
                'service_enable' => false,
              )
            is_expected.not_to contain_echo('automount')
          else
            is_expected.not_to create_class('autofs')
            is_expected.to contain_echo('automount')
              .with(
                'message'  => 'automounting',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
