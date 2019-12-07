require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::sles::sec_crond' do
  enforce_options.each do |enforce|
    context "Suse with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Suse',
          operatingsystem: 'SLES',
          architecture: 'x86_64',
          'security_baseline' => {
            'services_enabled' => {
              'srv_crond' => 'disabled',
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'cron daemon',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_service('cron')
            .with(
              'ensure' => 'running',
              'enable' => true,
            )
          is_expected.not_to contain_echo('crond')
        else
          is_expected.not_to contain_service('crond')
          is_expected.to contain_echo('crond')
            .with(
              'message'  => 'cron daemon',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
