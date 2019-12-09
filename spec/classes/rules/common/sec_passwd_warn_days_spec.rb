require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_passwd_warn_days' do
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
                  'min_days_between_password_change' => 14,
                  'password_date_valid' => false,
                  'password_expires_days' => 82,
                  'password_inactive_days' => 35,
                  'warn_days_between_password_change' => 14,
                },
              },
              'pw_data' => {
                'pass_max_days_status' => true,
                'inactive_status' => true,
                'inactive' => 25,
                'pw_change_in_future' => true,
                'pass_min_days_status' => true,
                'pass_warn_age_status' => true,
              },
            },
          )
        end
        let(:params) do
          {
            'enforce' => enforce,
            'message' => 'password minimum warning days',
            'log_level' => 'warning',
            'warn_pass_days' => 7,
          }
        end

        it {
          is_expected.to compile
          if enforce
            is_expected.to contain_file_line('password warning days')
              .with(
                'ensure' => 'present',
                'path'   => '/etc/login.defs',
                'line'   => "PASS_WARN_AGE ${warn_pass_days}",
                'match'  => '^#?PASS_WARN_AGE',
              )
            
            is_expected.to contain_exec('chage --warndays 7 test1')
              .with(
                'path' => ['/bin', '/usr/bin', '/sbin', '/usr/sbin'],
              )

            is_expected.not_to contain_echo('pass-min-warn-days')
          else
            is_expected.not_to contain_exec('chage --warndays 7 test1')
            is_expected.to contain_echo('pass-min-warn-days')
              .with(
                'message'  => 'password minimum warning days',
                'loglevel' => 'warning',
                'withpath' => false,
              )
          end
        }
      end
    end
  end
end
