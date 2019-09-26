# return facts about kernel modules

def get_facts_kernel_modules
  kernel_modules = {}
  modules = ['cramfs', 'dccp', 'freevxfs', 'hfs', 'hfsplus', 'jffs2', 'rds', 'sctp', 'squashfs', 'tipc', 'udf', 'vfat']

  modules.each do |mod|
    kernel_modules[mod] = check_kernel_module(mod)
  end

  kernel_modules
end
