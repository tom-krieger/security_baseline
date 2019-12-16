require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_rhnsd' do
  enforce_options.each do |enforce|
    context "on RedHat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'RedHat',
          architecture: 'x86_64',
          'srv_avahi' => 'enabled',
          'security_baseline' => {
            'services_enabled' => {
              'srv_rhnsd' => 'enabled',
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'rhnsd service',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_service('rhnsd')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )
          is_expected.not_to contain_echo('rhnsd')
        else
          is_expected.not_to contain_service('rhnsd')
          is_expected.to contain_echo('rhnsd')
            .with(
              'message'  => 'rhnsd service',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
