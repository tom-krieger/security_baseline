require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_rsyncd' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'services_enabled' => {
                'srv_rsyncd' => 'enabled',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'rsyncd service',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_service('rsyncd')
              .with(
                'ensure' => 'stopped',
                'enable' => false,
              )
            is_expected.not_to contain_echo('rsyncd')
          else
            is_expected.not_to contain_service('rsyncd')
            is_expected.to contain_echo('rsyncd')
              .with(
                'message'  => 'rsyncd service',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
