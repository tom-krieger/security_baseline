require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_prelink' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            packages_installed: {
              mcstrans_pkg: true,
              prelink: true,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'prelink package',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_package('prelink')
            .with(
              'ensure' => 'absent',
            )

          is_expected.to contain_exec('reset prelink')
            .with(
              'command' => 'prelink -ua',
              'path'    => ['/bin', '/sbin', '/usr/bin', '/usr/sbin'],
              'onlyif'  => 'test -f /usr/sbin/prelink',
            )
            .that_comes_before('Package[prelink]')

          is_expected.not_to contain_echo('prelink')
        else
          is_expected.not_to contain_package('prelink')
          is_expected.to contain_echo('prelink')
            .with(
              'message'  => 'prelink package',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
