Puppet::Functions.create_function(:'security_baseline::init') do
  dispatch :init do
  end

  require 'puppet/tools/helper'

  def init
    remove_old_file
  end
end
