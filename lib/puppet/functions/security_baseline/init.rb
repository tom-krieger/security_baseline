Puppet::Functions.create_function(:'security_baseline::init') do
  dispatch :init do
  end

  require 'helper'

  def init
    remove_old_file
  end
end
