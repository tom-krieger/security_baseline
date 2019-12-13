require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_service_echo' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            inetd_services: {
              srv_echo: {
                status: true,
                filename: '/etc/xinetd.d/echo',
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'service echo',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_file_line('echo_disable')
          .with(
            'line'     => 'disable     = yes',
            'path'     => '/etc/xinetd.d/echo',
            'match'    => 'disable.*=',
            'multiple' => true,
          )

          is_expected.not_to contain_echo('echo-inetd')
        else
          is_expected.not_to contain_service('echo_discard')
          is_expected.to contain_echo('echo-inetd')
            .with(
              'message'  => 'service echo',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
