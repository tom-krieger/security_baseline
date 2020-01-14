require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_nis' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          'security_baseline' => {
            'services_enabled' => {
              'srv_nis' => 'enabled',
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
          is_expected.to contain_service('nis')
            .with(
              'ensure' => 'stopped',
              'enable' => false,
            )
          is_expected.not_to contain_echo('nis')
        else
          is_expected.not_to contain_service('nis')
          is_expected.to contain_echo('nis')
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
