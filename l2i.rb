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
                    s.puts ":lingr 001 #{params[:user]} :lingr irc gateway"
                    s.puts ":lingr 376 #{params[:user]} :End of MOTD command."
                    l.rooms.each do |r|
                        puts "room loop"
                        member = []
                        str = ":lingr 353 #{params[:user]} = ##{r.id} :"
                        r.members.each do |m|
                            member << m.username if m.presence
                        end
                        str += member.join(' ')
                        puts ":#{l.params[:user]} JOIN ##{r.id}"
                        s.puts ":#{l.params[:user]} JOIN ##{r.id}"
                        puts str
                        s.puts str
                        puts ":lingr 366 #{l.params[:user]} ##{r.id} :End of NAMES list"
                        s.puts ":lingr 366 #{l.params[:user]} ##{r.id} :End of NAMES list"
                    end
                },sock)

                l.events.register('new_message','ircg',lambda{|e,s,l|
                    puts "new message"
                    e.each do |n|
                        sock.puts ":#{n.user.username} PRIVMSG ##{n.room} :#{n.text}" if params[:user] != n.user.username
                    end
                },sock)
                l.events.register('status_changed','ircg',lambda{|e,s,l|
                    e.each do |n|
                        if n.presence && member.index(n.username).nil?
                            member << n.username 
                            s.puts ":#{n.username} JOIN :##{n.room}"
                        else
                            member.delete_if{|m| n.username == m }
                            s.puts ":#{n.username} PART :##{n.room}"
                        end
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
        l.shutdown
        sock.close
    end
end
