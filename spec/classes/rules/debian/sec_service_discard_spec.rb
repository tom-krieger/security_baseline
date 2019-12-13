require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_service_discard' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            inetd_services: {
              srv_discard: {
                status: true,
                filename: '/etc/xinetd.d/discard',
              },
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'service discard',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_file_line('discard_disable')
            .with(
              'line'     => 'disable     = yes',
              'path'     => '/etc/xinetd.d/discard',
              'match'    => 'disable.*=',
              'multiple' => true,
            )

          is_expected.not_to contain_echo('discard-inetd')
        else
          is_expected.not_to contain_service('discard_disable')
          is_expected.to contain_echo('discard-inetd')
            .with(
              'message'  => 'service discard',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
