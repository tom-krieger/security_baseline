require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_service_tftp' do
  enforce_options.each do |enforce|
    context "Suse with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Suse',
          operatingsystem: 'SLES',
          architecture: 'x86_64',
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
          'message' => 'service tftp',
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

          is_expected.to contain_service('tftp-udp')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.not_to contain_echo('tftp-service')
        else
          is_expected.not_to contain_service('tftp')
          is_expected.not_to contain_service('tftp-udp')
          is_expected.to contain_echo('tftp-service')
            .with(
              'message'  => 'service tftp',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
