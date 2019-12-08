require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_tftp' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'services_enabled' => {
                'srv_tftp.socket' => 'enabled',
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'tftp.socket service',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_service('tftp.socket')
              .with(
                'ensure' => 'stopped',
                'enable' => false,
              )
            is_expected.not_to contain_echo('tftp-server')
          else
            is_expected.not_to contain_service('tftp.socket')
            is_expected.to contain_echo('tftp-server')
              .with(
                'message'  => 'tftp.socket service',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
