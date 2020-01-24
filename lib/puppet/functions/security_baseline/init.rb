Puppet::Functions.create_function(:'security_baseline::init') do
  dispatch :init do
    required_param 'String', :filename
  end

  def init(filename)
    call_function('debug', 'init called')
    call_function('info', 'init called')
    File.delete(filename) if File.exist?(filename)
    File.open(filename, 'w') do |file|
      file.puts("ok:\n")
      file.puts("fail:\n")
      file.puts("unknown:\n")
    end

    nil
  end
end