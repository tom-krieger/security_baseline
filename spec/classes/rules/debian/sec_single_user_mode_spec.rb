require 'spec_helper'

enforce_options = [true, false]

describe 'security_baseline::rules::common::sec_single_user_mode' do
  enforce_options.each do |enforce|
    context "on Debian with enforce = #{enforce}" do
      let(:facts) do
        {
          osfamily: 'Suse',
          operatingsystem: 'SLES',
          architecture: 'x86_64',
          security_baseline: {
            single_user_mode: {
              rootpw: 'none',
            },
          },
          selinux_config_mode: 'disabled',
        }
      end
      let(:params) do
        {
          'enforce' => enforce,
          'message' => 'single user mode',
          'log_level' => 'warning',
        }
      end

      it { is_expected.to compile }
      it do
        is_expected.to contain_echo('single_user_mode')
          .with(
            'message'  => 'single user mode',
            'loglevel' => 'warning',
            'withpath' => false,
          )
      end
    end
  end
end
