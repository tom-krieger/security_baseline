# get a value with sysctl command
# params:
#    value to read

def read_sysctl_value(value)
  ret = ''
  val = Facter::Core::Execution.exec("sysctl #{value}").split(%r{=})
  if !val.nil? && !val.empty?
    ret = val[1].strip
  end

  ret
end
