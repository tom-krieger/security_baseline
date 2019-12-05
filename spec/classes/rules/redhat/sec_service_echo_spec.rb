require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_service_echo' do
  context 'RedHat' do
    let(:facts) { {
      :osfamily => 'RedHat',
      :operatingsystem => 'CentOS',
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
      is_expected.to contain_service('echo-dgram')
        .with(
          'ensure' => 'stopped',
          'enable' => false,
        )

      is_expected.to contain_service('echo-stream')
        .with(
          'ensure' => 'stopped',
          'enable' => false,
        )
    end
  end
end
