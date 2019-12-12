require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_rsh' do
  enforce_options.each do |enforce|
    context "on RedHat with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          security_baseline: {
            services_enabled: {
              srv_rsh: 'enabled',
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'rsh service',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_service('rsh.socket')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )
          is_expected.to contain_service('rlogin.socket')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )
          is_expected.to contain_service('rexec.socket')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )
          is_expected.not_to contain_echo('rsh-service')
        else
          is_expected.not_to contain_service('rsh.socket')
          is_expected.not_to contain_service('rlogin.socket')
          is_expected.not_to contain_service('rexec.socket')
          is_expected.to contain_echo('rsh-service')
            .with(
              'message'  => 'rsh service',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
