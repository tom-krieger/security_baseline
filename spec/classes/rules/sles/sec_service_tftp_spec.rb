require 'spec_helper'

describe 'security_baseline::rules::sles::sec_service_tftp' do
  context 'Suse' do
    let(:facts) { {
      :osfamily => 'Suse',
      :operatingsystem => 'SLES',
      :architecture => 'x86_64',
    } }
    let(:params) do
      {
        'enforce' => true,
        'message' => 'service chargen',
        'loglevel' => 'warning',
      }
    end

    it { is_expected.to compile }
    it do
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
    end
  end
end
