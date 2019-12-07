require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_avahi' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'srv_avahi' => 'enabled',
            'security_baseline' => {
              'services_enabled' => {
                'srv_avahi-daemon' => 'enabled',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'avahi service',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_service('avahi-daemon')
              .with(
                'ensure' => 'stopped',
                'enable' => false,
              )
            is_expected.not_to contain_echo('avahi-daemon')
          else
            is_expected.not_to contain_service('avahi-daemon')
            is_expected.to contain_echo('avahi-daemon')
              .with(
                'message'  => 'avahi service',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
