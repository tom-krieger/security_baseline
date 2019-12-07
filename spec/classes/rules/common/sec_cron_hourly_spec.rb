require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_cron_hourly' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'cron' => {
                '/etc/cron.hourly' => {
                  'uid' => 0,
                  'gid' => 100,
                  'mode' => '0666',
                },
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'cron hourly',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file('/etc/cron.hourly')
              .with(
                'ensure' => 'directory',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0700',
              )

            is_expected.not_to contain_echo('etc-cron-hourly')
          else
            is_expected.not_to contain_file('/etc/cron.daily')
            is_expected.to contain_echo('etc-cron-hourly')
              .with(
                'message'  => 'cron hourly',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
