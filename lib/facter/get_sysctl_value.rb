# get a value with sysctl command
# params:
#    value to read

def get_sysctl_value(value)
  val = Facter::Core::Execution.exec("sysctl #{value}").split(/=/)
  val[1].strip()
end