# check if a kernelmodule is installed

def check_kernel_module(mod)
  installed = Facter::Core::Execution.exec("lsmod | grep #{mod}")
    if installed.empty?
      false
    else
      true
    end
  end
