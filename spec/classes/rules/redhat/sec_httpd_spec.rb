require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_httpd' do
  enforce_options.each do |enforce|
    context "on RedHat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'srv_avahi' => 'enabled',
          'security_baseline' => {
            'services_enabled' => {
              'srv_httpd' => 'enabled',
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'httpd service',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_service('httpd')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )
          is_expected.not_to contain_echo('httpd')
        else
          is_expected.not_to contain_service('httpd')
          is_expected.to contain_echo('httpd')
            .with(
              'message'  => 'httpd service',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
