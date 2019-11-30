# return facts about kernel modules

def read_facts_kernel_modules(modules)
  kernel_modules = {}

  modules.each do |mod|
    kernel_modules[mod] = check_kernel_module(mod)
  end

  kernel_modules
end
