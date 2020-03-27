
shared_examples 'common::rules' do

  puts 'Common tests'
  
  context 'rule 1.1.1.1: cramfs' do
    describe file('/etc/modprobe.d/cramfs.conf') do
      it { should be_file }
      its(:content) { should match /install cramfs \/bin\/true/ }
    end
  end

  context 'rule 1.1.1.2: freexvfs' do
    describe file('/etc/modprobe.d/freevxfs.conf') do
      it { should be_file }
      its(:content) { should match /install freevxfs \/bin\/true/ }
    end
  end

  context 'rule 1.1.1.3: jffs2' do
    describe file('/etc/modprobe.d/jffs2.conf') do
      it { should be_file }
      its(:content) { should match /install jffs2 \/bin\/true/ }
    end
  end
end
