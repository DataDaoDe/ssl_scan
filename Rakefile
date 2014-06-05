require "bundler/gem_tasks"
require "net/http"
require "ssl_scan/util"

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

namespace :ssl do
  desc 'fetch cacert from curl site' 
  task :get_cert do
    uri = URI("http://curl.haxx.se")
    http = Net::HTTP.new(uri.host, uri.port) 
    req  = Net::HTTP::Get.new('/ca/cacert.pem')
    res  = http.request(req)
    target_file = File.join(SSLScan::Util::ROOT, "data/cacert.pem")
    File.open(target_file, "w+") do |f|
      puts "writing to file: #{target_file}"
      f.write(res.body)
    end
  end
end