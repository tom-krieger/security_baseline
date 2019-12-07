require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_cron_weekly' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'cron' => {
                '/etc/cron.weekly' => {
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
            'message' => 'cron weekly',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file('/etc/cron.weekly')
              .with(
                'ensure' => 'directory',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0700',
              )
            is_expected.not_to contain_echo('etc-cron-weekly')
          else
            is_expected.not_to contain_file('/etc/cron.weekly')
            is_expected.to contain_echo('etc-cron-weekly')
              .with(
                'message'  => 'cron weekly',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
