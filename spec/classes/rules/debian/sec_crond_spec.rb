require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_crond' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          'security_baseline' => {
            'services_enabled' => {
              'srv_cron' => 'disabled',
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
          is_expected.not_to contain_service('cron')
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
