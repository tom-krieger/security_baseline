require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_etc_crontab' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'cron' => {
                '/etc/crontab' => {
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
            'message' => 'crontab',
            'log_level' => 'warning',
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file('/etc/crontab')
              .with(
                'ensure' => 'present',
                'owner'  => 'root',
                'group'  => 'root',
                'mode'   => '0600',
              )

            is_expected.not_to contain_echo('etc-crontab')
          else
            is_expected.not_to contain_file('/etc/crontab')
            is_expected.to contain_echo('etc-crontab')
              .with(
                'message'  => 'crontab',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
