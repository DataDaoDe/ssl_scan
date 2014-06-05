require "bundler/gem_tasks"

namespace :gettext do

  desc 'generate mo files'
  task :mo do
    src = 'ssl_scan.po'
    target = 'ssl_scan.mo'
    Dir["locale/**"].each do |dir|
      cmd = "msgfmt #{File.join(dir, src)} -o #{File.join(dir, 'LC_MESSAGES', target)}"
      puts "Running command: #{cmd}"
      system(cmd)
    end
  end

end