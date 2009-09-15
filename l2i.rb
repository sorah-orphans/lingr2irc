=begin
    l2i.rb
    Author:: Sora Harakami <sora134@gmail.com>
    License:: MIT License
=end
require "lingr.rb"
require "socket"

$port ||= 6669

s = TCPServer.open($port)

loop do
    Thread.new(s.accept) do |sock|
        params = {}
        puts "accept"
        while buf = sock.gets.chomp
            if /NICK (.+)/i =~ buf
                params[:user] = $1
                puts "user set"
            elsif /PASS (.+)/i =~ buf
                params[:password] = $1
                puts "pass set"
            elsif /USER/i =~ buf
                puts "boot"
                l = Lingr.new(params)
                p l
                l.debug = true
                l.events.register('boot_complete','ircg',lambda{|e,s,l|
                    puts "booted"
                    p s
                    l.rooms.each do |r|
                        puts "room loop"
                        p r.members
                        str = ":lingr 353 #{params[:user]} #{r.id} :"
                        r.members.each do |m|
                            p m
                            str += "#{m.username} "# if m.presence
                        end
                        puts str
                        s.puts str
                    end
                },sock)
                l.events.register('new_message','ircg',lambda{|e,s,l|
                    puts "new message"
                    e.each do |n|
                        sock.puts ":#{n.user.username} PRIVMSG ##{n.room} :#{n.text}"
                    end
                },sock)
                Thread.new do
                    l.boot
                end
            elsif /QUIT/i =~ buf
                puts "shutdown"
                l.shutdown
                sock.close
                Thread.exit
            elsif /PRIVMSG #(.+) :(.+)/i =~ buf
                puts "say"
                l.say($1,$2)
            end
               
        end
        sock.close
    end
end
