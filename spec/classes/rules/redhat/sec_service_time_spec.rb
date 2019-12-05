require 'spec_helper'

describe 'security_baseline::rules::redhat::sec_service_time' do
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
  end
end
