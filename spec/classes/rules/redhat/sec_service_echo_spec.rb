require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_service_echo' do

  enforce_options.each do |enforce|

    context "RedHat with enforce = #{enforce}" do
      let(:facts) { {
        :osfamily => 'RedHat',
        :operatingsystem => 'CentOS',
        :architecture => 'x86_64',
        :srv_echo => true,
        :security_baseline => {
          :xinetd_services => {
            :srv_echo => true
          }
        }
      } }

      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'servive echo',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
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

          is_expected.not_to contain_echo('echo-service')
        else
          is_expected.not_to contain_service('echo-dgram')
          is_expected.not_to contain_service('echo-stream')
          is_expected.to contain_echo('echo-service')
            .with(
              'message'  => 'servive echo',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
