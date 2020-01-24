Puppet::Functions.create_function(:'security_baseline::init') do
  dispatch :init do
    required_param 'String', :filename
  end

  def init(filename)
    File.delete(filename) if File.exist?(filename)
    begin
      File.open(filename, 'w') do |fd|
        fd.puts("ok:\n")
        fd.puts("fail:\n")
        fd.puts("unknown:\n")
      end
    rescue
      raise Puppet::ParseError, ("security_baseline::init failed to write file #{filename}")
    end

    nil
  end
end