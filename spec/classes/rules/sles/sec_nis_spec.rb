require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_nis' do
  enforce_options.each do |enforce|
    context "on Suse SLES with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Suse',
          operatingsystem: 'SLES',
          architecture: 'x86_64',
          'security_baseline' => {
            'services_enabled' => {
              'srv_ypserv' => 'enabled',
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'nis service',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_service('ypserv')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )
          is_expected.not_to contain_echo('ypserv')
        else
          is_expected.not_to contain_service('ypserv')
          is_expected.to contain_echo('ypserv')
            .with(
              'message'  => 'nis service',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
