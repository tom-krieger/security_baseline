require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_service_time' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            inetd_services: {
              srv_time: {
                status: true,
                filename: '/etc/xinetd.d/time',
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'service time',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_file_line('time_disable')
            .with(
              'line'     => 'disable     = yes',
              'path'     => '/etc/xinetd.d/time',
              'match'    => 'disable.*=',
              'multiple' => true,
            )

          is_expected.not_to contain_echo('time-inetd')
        else
          is_expected.not_to contain_service('time_disable')
          is_expected.to contain_echo('time-inetd')
            .with(
              'message'  => 'service time',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
