require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_service_daytime' do

  enforce_options.each do |enforce|

    context "Suse with enforce = #{enforce}" do
      let(:facts) { {
        :osfamily => 'Suse',
        :operatingsystem => 'SLES',
        :architecture => 'x86_64',
        :security_baseline => {
          :xinetd_services => {
            :srv_daytime => true
          }
        }
      } }
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'service daytime',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_service('daytime')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )

          is_expected.to contain_service('daytime-udp')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )
            
          is_expected.not_to contain_echo('daytime-service')
        else
          is_expected.not_to contain_service('daytime')
          is_expected.not_to contain_service('daytime-udp')
          is_expected.to contain_echo('daytime-service')
            .with(
              'message'  => 'service daytime',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
