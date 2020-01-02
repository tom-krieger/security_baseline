require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_service_tftp' do
  enforce_options.each do |enforce|
    context "RedHat 7 with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemmajrelease: '7',
          architecture: 'x86_64',
          srv_tftp: true,
          security_baseline: {
            xinetd_services: {
              srv_tftp: true,
            },
          },
        }
      end

      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'servive tftp',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_service('tftp-dgram')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.to contain_service('tftp-stream')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.not_to contain_echo('tftp-service')
        else
          is_expected.not_to contain_service('tftp-dgram')
          is_expected.not_to contain_service('tftp-stream')
          is_expected.to contain_echo('tftp-service')
            .with(
              'message'  => 'servive tftp',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end

    context "RedHat 6 with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'RedHat',
          operatingsystem: 'CentOS',
          operatingsystemmajrelease: '6',
          architecture: 'x86_64',
          srv_tftp: true,
          security_baseline: {
            xinetd_services: {
              srv_tftp: true,
            },
          },
        }
      end

      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'servive tftp',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_service('tftp')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.not_to contain_echo('tftp-service')
        else
          is_expected.not_to contain_service('tftp')
          is_expected.to contain_echo('tftp-service')
            .with(
              'message'  => 'servive tftp',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
