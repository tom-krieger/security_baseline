# check if a kernelmodule is installed

def check_kernel_module(mod)
  instmod = Facter::Core::Execution.exec("modprobe -n -v #{mod}")
  installed = Facter::Core::Execution.exec("lsmod | grep #{mod}")
  if installed.empty? && (instmod.match(%r{install\s*/bin/true}) || instmod.match(%r{not found})
    false
  else
    true
  end
end
