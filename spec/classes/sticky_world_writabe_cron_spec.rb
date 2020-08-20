# frozen_string_literal: true

require 'spec_helper'

describe 'security_baseline::sticky_world_writabe_cron' do
  on_supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:facts) { os_facts }

      it {
        is_expected.to compile
        is_expected.to contain_file('/usr/share/security_baseline/bin/sticy-world-writable.sh')
          .with(
            'ensure'  => 'present',
            'owner'   => 'root',
            'group'   => 'root',
            'mode'    => '0700',
          )

        is_expected.to contain_file('/etc/cron.d/sticky-world-writebale.cron')
          .with(
            'ensure' => 'present',
            'source' => 'puppet:///modules/security_baseline/sticky-world-writeable.cron',
            'owner'  => 'root',
            'group'  => 'root',
            'mode'   => '0644',
          )
      }
    end
  end
end
