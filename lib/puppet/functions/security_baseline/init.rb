require 'lib/puppet/functions/security_baseline/helper'

Puppet::Functions.create_function(:'security_baseline::init') do

  dispatch :init do
  end

  def init
    remove_old_file
  end
end