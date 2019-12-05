require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_service_chargen' do
  context 'RedHat' do
    let(:facts) { {
      :osfamily => 'RedHat',
      :operatingsystem => 'CentOS',
      :architecture => 'x86_64',
      :srv_chargen => true,
    } }

    it { is_expected.to compile }
    it do
      is_expected.to contain_service('chargen-dgram')
        .with(
          'ensure' => 'stopped',
          'enable' => false,
        )

      is_expected.to contain_service('chargen-stream')
        .with(
          'ensure' => 'stopped',
          'enable' => false,
        )
    end
  end
end
