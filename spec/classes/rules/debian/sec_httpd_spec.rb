require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_httpd' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          'security_baseline' => {
            'services_enabled' => {
              'srv_apache2' => 'enabled',
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'apache2 service',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_service('apache2')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )
          is_expected.not_to contain_echo('apache2')
        else
          is_expected.not_to contain_service('apache2')
          is_expected.to contain_echo('apache2')
            .with(
              'message'  => 'apache2 service',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
