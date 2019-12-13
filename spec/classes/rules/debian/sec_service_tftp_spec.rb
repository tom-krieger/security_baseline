require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_service_tftp' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            inetd_services: {
              srv_tftp: {
                status: true,
                filename: '/etc/xinetd.d/tftp',
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'service tftp',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_file_line('tftp_disable')
            .with(
              'line'     => 'disable     = yes',
              'path'     => '/etc/xinetd.d/tftp',
              'match'    => 'disable.*=',
              'multiple' => true,
            )

          is_expected.not_to contain_echo('tftp-inetd')
        else
          is_expected.not_to contain_service('tftp_disable')
          is_expected.to contain_echo('tftp-inetd')
            .with(
              'message'  => 'service tftp',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
