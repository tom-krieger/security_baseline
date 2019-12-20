require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_firewalld_service' do
  enforce_options.each do |enforce|
    context "RedHat with enforce #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          architecture: 'x86_64',
          'security_baseline' => {
            'services_enabled' => {
              'srv_firewalld' => false,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'firewalld service',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_service('firewalld')
            .with(
              'ensure' => 'running',
              'enable' => true,
            )
          is_expected.not_to contain_echo('firewalld-service')
        else
          is_expected.not_to contain_service('firewalld')
          is_expected.to contain_echo('firewalld-service')
            .with(
              'message'  => 'firewalld service',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
