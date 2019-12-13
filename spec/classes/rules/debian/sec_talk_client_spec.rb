require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::debian::sec_talk_client' do
  enforce_options.each do |enforce|
    context "Suse with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Debian',
          operatingsystem: 'Ubuntu',
          architecture: 'x86_64',
          security_baseline: {
            packages_installed: {
              talk: true,
            },
          },
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'talk package',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        if enforce
          is_expected.to contain_package('talk')
            .with(
              'ensure' => 'absent',
            )

          is_expected.not_to contain_echo('talk-client')
        else
          is_expected.not_to contain_package('talk')
          is_expected.to contain_echo('talk-client')
            .with(
              'message'  => 'talk package',
              'loglevel' => 'warning',
              'withpath' => false,
            )
        end
      end
    end
  end
end
