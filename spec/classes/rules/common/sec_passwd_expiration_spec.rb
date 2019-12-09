require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_passwd_expiration' do
  on_supported_os.each do |os, os_facts|
    enforce_options.each do |enforce|
      context "on #{os} with enforce = #{enforce}" do
        let(:facts) do
          os_facts.merge(
            'security_baseline' => {
              'local_users' => {
                'test1' => {
                  'account_expires_days' => 25,
                  'last_password_change_days' => 8,
                  'max_days_between_password_change' => 120,
                  'min_days_between_password_change' => 7,
                  'password_date_valid' => true,
                  'password_expires_days' => 82,
                  'password_inactive_days' => 30,
                  'warn_days_between_password_change' => 7,
                },
              },
              'pw_data' => {
                'pass_max_days_status' => true,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'password expiration',
            'log_level' => 'warning',
            'max_pass_days' => 90,
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file_line('password expiration policy')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/login.defs',
                'line'   => 'PASS_MAX_DAYS 90',
                'match'  => '^#?PASS_MAX_DAYS',
              )
            is_expected.to contain_exec('chage --maxdays 90 test1')
              .with(
                'path' => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              )

            is_expected.not_to contain_echo('pass-max-days')
          else
            is_expected.not_to contain_file_line('password expiration policy')
            is_expected.not_to contain_exec('chage --maxdays 90 test1')
            is_expected.to contain_echo('pass-max-days')
              .with(
                'message'  => 'password expiration',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
