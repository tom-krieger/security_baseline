require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_systemd_timesyncd' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Suse',
          operatingsystem: 'SLES',
          architecture: 'x86_64',
          security_baseline: {
            services_enabled: {
              'systemd-timesyncd' => 'disabled',
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'systemd timesyncd config',
          'log_level' => 'warning',
          'ntp_servers' => ['0.de.pool.ntp.org', '1.de.pool.ntp.org', '2.de.pool.ntp.org'],
          'ntp_fallback_servers' => ['3.de.pool.ntp.org'],
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_file_line('ntp-timesyncd.conf')
            .with(
              'path'               => '/etc/systemd/timesyncd.conf',
              'line'               => 'NTP=0.de.pool.ntp.org 1.de.pool.ntp.org 2.de.pool.ntp.org',
              'match'              => '^NTP=',
              'append_on_no_match' => true,
            )

          is_expected.to contain_file_line('ntp-fallback-timesyncd.conf')
            .with(
              'path'               => '/etc/systemd/timesyncd.conf',
              'line'               => 'FallbackNTP=3.de.pool.ntp.org',
              'match'              => '^FallbackNTP=',
              'append_on_no_match' => true,
            )
            
          is_expected.not_to contain_echo('systemd_timesyncd')
        else
          is_expected.not_to contain_file_line('ntp-timesyncd.conf')
          is_expected.not_to contain_file_line('ntp-fallback-timesyncd.conf')
          is_expected.to contain_echo('systemd_timesyncd')
            .with(
              'message'  => 'systemd timesyncd config',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
