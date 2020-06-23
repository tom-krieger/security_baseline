# frozen_string_literal: true

require 'puppet_litmus'
require 'singleton'

class Helper
  include Singleton
  include PuppetLitmus
end

def some_helper_method
  Helper.instance.bolt_run_script('path/to/file')
end

def run_fact
  run_shell('cd /etc/puppetlabs/code/environments/production/modules/security_baseline/lib ; facter -j -p --custom-dir . facter/security_baseline')
end
