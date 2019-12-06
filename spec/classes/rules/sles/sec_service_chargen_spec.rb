require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_service_time' do
  enforce_options.each do |enforce|
    context "Suse with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Suse',
          operatingsystem: 'SLES',
          architecture: 'x86_64',
          security_baseline: {
            xinetd_services: {
              srv_time: true,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'service time',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_service('time')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.to contain_service('time-udp')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.not_to contain_echo('time-service')
        else
          is_expected.not_to contain_service('time')
          is_expected.not_to contain_service('time-udp')
          is_expected.to contain_echo('time-service')
            .with(
              'message'  => 'service time',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
