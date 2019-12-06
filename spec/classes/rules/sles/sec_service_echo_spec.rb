require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_service_echo' do

  enforce_options.each do |enforce|

    context "Suse with enforce = #{enforce}" do
      let(:facts) { {
        :osfamily => 'Suse',
        :operatingsystem => 'SLES',
        :architecture => 'x86_64',
        :security_baseline => {
          :xinetd_services => {
            :srv_echo => true
          }
        }
      } }
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'service echo',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_service('echo')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.to contain_service('echo-udp')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )
            
          is_expected.not_to contain_echo('echo-service')
        else
          is_expected.not_to contain_service('echo')
          is_expected.not_to contain_service('echo-udp')
          is_expected.to contain_echo('echo-service')
            .with(
              'message'  => 'service echo',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
