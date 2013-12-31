desc "run specs"
task :spec do
    $LOAD_PATH.unshift '.', 'spec', 'lib'
    require 'spec/spec_helper'
    Minitest.autorun
    Dir.glob('spec/**/*_spec.rb') do |file|    
      load file
    end
end

task :test => :spec
task :default => [:test]
