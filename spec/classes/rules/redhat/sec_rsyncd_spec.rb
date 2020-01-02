require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_rsyncd' do
  enforce_options.each do |enforce|
    context "on RedHat 7 with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemmajrelease: '7',
          architecture: 'x86_64',
          'security_baseline' => {
            'services_enabled' => {
              'srv_rsyncd' => 'enabled',
            },
            'xinetd_services' => {
              'srv_rsync' => true,
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

    context "on RedHat 6 with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemmajrelease: '6',
          architecture: 'x86_64',
          'security_baseline' => {
            'services_enabled' => {
              'srv_rsyncd' => 'enabled',
            },
            'xinetd_services' => {
              'srv_rsync' => true,
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
          is_expected.to contain_service('rsync')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )
          is_expected.not_to contain_echo('rsyncd')
        else
          is_expected.not_to contain_service('rsync')
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
