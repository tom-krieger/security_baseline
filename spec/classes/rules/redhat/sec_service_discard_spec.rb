require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::redhat::sec_service_discard' do

  enforce_options.each do |enforce|

    context "RedHat with enforce = #{enforce}" do
      let(:facts) { {
        :osfamily => 'RedHat',
        :operatingsystem => 'CentOS',
        :architecture => 'x86_64',
        :srv_discard => true,
        :security_baseline => {
          :xinetd_services => {
            :srv_discard => true
          }
        }
      } }

      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'servive discard',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_service('discard-dgram')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.to contain_service('discard-stream')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.not_to contain_echo('discard-service')
        else
          is_expected.not_to contain_service('discard-dgram')
          is_expected.not_to contain_service('discard-stream')
          is_expected.to contain_echo('discard-service')
            .with(
              'message'  => 'servive discard',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
