Puppet::Functions.create_function(:'security_baseline::init') do
  dispatch :init do
    required_param 'String', :filename
  end

  def init(filename)
    File.delete(filename) if File.exist?(filename)

    nil
  end
end
