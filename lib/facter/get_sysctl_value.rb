# get a value with sysctl command
# params:
#    value to read

def get_sysctl_value(value)
  ret = ''
  val = Facter::Core::Execution.exec("sysctl #{value}").split(/=/)
  if ! val.nil? and ! val.empty?
    ret = val[1].strip()
  end
  
  ret
end