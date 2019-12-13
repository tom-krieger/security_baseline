require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_rsyncd' do
  enforce_options.each do |enforce|
    context "on RedHat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'security_baseline' => {
            'services_enabled' => {
              'srv_rsyncd' => 'enabled',
            },
          },
        }
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
