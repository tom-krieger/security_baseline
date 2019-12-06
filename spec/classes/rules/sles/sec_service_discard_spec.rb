require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_service_discard' do

  enforce_options.each do |enforce|

    context "Suse with enforce = #{enforce}" do
      let(:facts) { {
        :osfamily => 'Suse',
        :operatingsystem => 'SLES',
        :architecture => 'x86_64',
        :security_baseline => {
          :xinetd_services => {
            :srv_discard => true
          }
        }
      } }
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'service discard',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_service('discard')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.to contain_service('discard-udp')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )
            
          is_expected.not_to contain_echo('discard-service')
        else
          is_expected.not_to contain_service('discard')
          is_expected.not_to contain_service('discard-udp')
          is_expected.to contain_echo('discard-service')
            .with(
              'message'  => 'service discard',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
