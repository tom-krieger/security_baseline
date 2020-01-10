require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_disable_ipv6' do
  enforce_options.each do |enforce|
    context "Debian with enforce #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          'security_baseline' => {
            'grub_ipv6_disabled' => false,
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'grub disable ipv6',
          'log_level' => 'warning',
        }
      end

      it {
        is_expected.to compile
        if enforce
          is_expected.to contain_kernel_parameter('ipv6.disable')
            .with(
              'value' => '1',
            )

          is_expected.not_to contain_echo('grub-disable-ipv6')
        else
          is_expected.not_to contain_kernel_parameter('ipv6.disable')
          is_expected.to contain_echo('grub-disable-ipv6')
            .with(
              'message'  => 'grub disable ipv6',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      }
    end
  end
end
