require 'spec_helper'

describe 'security_baseline::rules::sles::sec_service_time' do
  context 'Suse' do
    let(:facts) do
      {
        osfamily: 'Suse',
        operatingsystem: 'SLES',
        architecture: 'x86_64',
        srv_time: true,
        security_baseline: {
          xinetd_services: {
            srv_time: true,
          },
        },
      }
    end
    let(:params) do
      {
        'enforce' => true,
        'message' => 'service chargen',
        'loglevel' => 'warning',
      }
    end

    it { is_expected.to compile }
    it do
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
    end
  end
end
