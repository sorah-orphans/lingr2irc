#-*- coding: utf-8 -*-
=begin
    lingr.rb
    Author:: Sora Harakami <sora134@gmail.com>
    License:: MIT License (X11 License)
    http://soralabo.net/
    http://codnote.net/
    
    
    ========================
    this code is imported WebAPI::JsonParser.
    JsonParser http://rubyforge.org/snippet/detail.php?type=snippet&id=148
    JsonParser license is public-domain.
=end

require "net/http"
require "thread"
require 'strscan'
require 'time'

class Lingr
    def initialize(params = {})
        @debug = false
        @cookie_key = "__lingr"
        @params = params
        @session = Lingr::Session.new(self)
        @c_error = 0
        @session_id = nil
        @nickname = nil
        @public_session_id = nil
        @counter = nil
        @booting = false
        @booted = false
        @local_say_count = 0
        @events = Lingr::Event.new(self)
        @room = Lingr::Rooms.new(self)
        @rooms = []
        @user = Lingr::User.new(self)
        @observe_thread = nil
    end

    def boot
        @booting = true
        puts "debug: booting..." if @debug
        puts "debug: session start" if @debug
        e_session_cv = lambda{|e,l|
            if l.booting
                puts "debug: get rooms" if @debug
                l.user.get_rooms
            end
        }
        @events.register('session_created','boot',e_session_cv)
        @events.register('session_verified','boot',e_session_cv)
        @events.register('get_rooms_complete','boot',lambda{|e,l|
            if l.booting
                puts "debug: room show" if @debug
                l.room.show(l.user.rooms.join(','))
            end
        })
        @events.register('room_show_complete','boot',lambda{|e,l|
            if l.booting
                puts "debug: unsubscribe" if @debug
                l.room.unsubscribe(l.user.rooms.join(','),true)
            end
        })
        @events.register('unsubscribe_complete','boot',lambda{|e,l|
            if l.booting
                puts "debug: unsubscribe complete" if @debug
                puts "debug: subscribe" if @debug
                l.room.subscribe(l.user.rooms.join(','))
            end
        })
        @events.register('subscribe_complete','boot',lambda{|e,l|
            if l.booting
                puts "debug: observe start" if @debug
                l.booting = false
                l.booted = true
                l.events.add('boot_complete')
                puts "debug: booted!" if @debug
                l.room.observe
            end
        })
        puts "debug: event added" if @debug
        @session.start()
    end

    def shutdown
        return unless @booted
        @observe_thread.kill unless @observe_thread.nil?
        puts "debug: shutdown going now.."
        @session.end()
        puts "debug: shutdowned."
        @booted = false
        @events.add('shutdown_complete')
    end

    def rooms
        return nil unless @booted
        return @rooms
    end

    def say(room_id,text)
        if room_id.kind_of?(String)
            @room.say(room_id,text,nil,@local_say_count)
        else
            @room.say(room_id.id,text,nil,@local_say_count)
        end
        @local_say_count += 1
    end

    def request(path, params = {}, options = {})
        Thread.new do
            puts "debug: request begin" if @debug
            options["success"] ||= lambda{|json,lingr|}
            options["failure"] ||= lambda{|json,lingr|}
            options["complete"] ||= lambda{|json,lingr|}
            options["observe"] ||= false
            params["callback"] = "foo"
            req = Net::HTTP::Get.new("/api"+path+"?"+params.map{|k,v| "#{k}=#{v}" }.join("&"))

            unless @session_id.nil?
                req['Cookie'] = @cookie_key+"="+@session_id
            end
            if options["observe"]
                n_http = Net::HTTP.new("lingr.com",8080)
            else
                n_http = Net::HTTP.new("lingr.com")
            end
            puts "debug: "+req.path if @debug
            i = 0
            begin
                n_http.request(req) do |h|
                    puts "debug: requested" if @debug
                    raw_json = h.body.gsub(/foo\(/,"").gsub(/\)/,"")
                    json = WebAPI::JsonParser.new.parse(raw_json)
                    if json["status"] == 'ok'
                        puts "debug: request call success" if @debug
                        t = Thread.new {options["success"].call(json,self)}
                    else
                        puts "debug: request call failure" if @debug
                        t = Thread.new {options["failure"].call(json,self)}
                    end
                    puts "debug: request call complete" if @debug
                    Thread.new {options["complete"].call(json,self)}.join
                    t.join
                    puts "debug: request complete" if @debug
                    Thread.exit
                end
            rescue EOFError => e
                i += 1
                puts "debug: request rescue (#{i.to_s}) (#{req.path})" if @debug
                puts "debug: reconnect" if @debug
                n_http.finish
                n_http.start
                puts "debug: retry request" if @debug
                retry
            end
        end.join
    end

    class Event
        def initialize(lingr)
            @lingr = lingr
            @event_ary = []
            @registers = {}
        end

        def add(name,data = nil)
            puts "debug: added #{name} event" if @lingr.debug
            @event_ary << [name,data]
            put_event()
        end

        def register(ev,n,l,s=nil)
            puts "debug: registered event capture #{ev} #{n}" if @lingr.debug
            @registers[ev] ||= []
            if @registers[ev].map{|x|x[0]}.index(n).nil?
                @registers[ev] << [n,l,s]
            end
        end

        def release(ev,n)
            @registers[ev].reject!{|p|
                p[0] == n
            }
        end

        private
        def recieve()
            @event_ary.shift
        end

        def put_event()
            puts "debug: put_event" if @lingr.debug
            threads = []
            while @event_ary.length > 0
                tmp = recieve
                puts "debug: put_event loop" if @lingr.debug
                @registers[tmp[0]] ||= []
                print "debug: " if @lingr.debug
                p @registers[tmp[0]] if @lingr.debug
                @registers[tmp[0]].each do |e|
                    puts "debug: put event" if @lingr.debug
                    print "debug: " if @lingr.debug
                    p e if @lingr.debug
                    threads << Thread.new do
                        if e[2].nil?
                            puts "debug: call lambda" if @lingr.debug
                            e[1].call(tmp[1],@lingr)
                        else
                            puts "debug: call lambda with self" if @lingr.debug
                            e[1].call(tmp[1],e[2],@lingr)
                        end
                    end
                end
            end
            threads.each{|t|t.join}
        end
    end

    class Rooms
        def initialize(lingr)
            @lingr = lingr
        end

        def show(room_id)
            @lingr.request('/room/show',{
                "session" => @lingr.session_id,
                "room" => room_id
            },{
                "success" => lambda{|json,lingr|
                json["rooms"].each do |n|
                    r = n["room"]["roster"]
                    members = []
                    mem = []
                    r["members"].each do |m|
                        members << Member.new(
                            :nickname => m["name"],
                            :username => m["username"],
                            :icon_url => m["icon_url"],
                            :presense => m["presense"] == 'online',
                            :owner => m["owner"]
                        )
                        mem << m["username"]
                    end
                    messages = []
                    n["room"]["messages"].each do |n|
                        m = n["message"]
                        unless m.nil?
                            messages << Message.new(
                                :timestamp => Time.parse(m["timestamp"]),
                                :text => m["text"],
                                :user => members[mem.index(m["speaker_id"])]
                            )
                        end
                    end
                    @lingr.rooms << Room.new(
                        :public => n["room"]["public"],
                        :name => n["room"]["name"],
                        :id => n["room"]["id"],
                        :description => n["room"]["blurb"],
                        :members => members,
                        :messages => messages
                    )
                end
                lingr.events.add('room_show_complete',json)
            },
                "failure" => lambda{|json,lingr|
                lingr.events.add('api_failure',json)
            }
            })
        end

        def subscribe(room_id)
            puts "debug: called subscribe #{room_id}" if @lingr.debug
            @lingr.request('/room/subscribe',{
                "session" => @lingr.session_id,
                "room" => room_id
            },{
                "success" => lambda{|json,lingr|
                @lingr.counter = json["counter"]
                @lingr.events.add('subscribe_complete',json)
            },
                "failure" => lambda{|json,lingr|
                @lingr.events.add('api_failure',json)
            }
            })
        end

        def unsubscribe(room_id,n=nil)
            puts "debug: called unsubscribe #{room_id}" if @lingr.debug
            params = {
                "session" => @lingr.session_id,
                "room" => room_id
            }
            params["not"] = n unless n.nil?
            @lingr.request('/room/unsubscribe', params, {
                "success" => lambda{|json,lingr|
                @lingr.counter = json["counter"]
                @lingr.events.add('unsubscribe_complete',json)
            },
                "failure" => lambda{|json,lingr|
                @lingr.events.add('api_failure',json)
            }
            })
        end

        def say(room_id,text,nickname=nil,local_echo_count)
            nickname = @lingr.nickname if nickname.nil?
            @lingr.request('/room/say',{
                "session" => @lingr.session_id,
                "room" => room_id,
                "nickname" => nickname,
                "text" => text,
                "local_id" => local_echo_count
            }, {
                "success" => lambda{|json,lingr|
                @lingr.events.add('say_complete',json)
            },
                "failure" => lambda{|json,lingr|
                @lingr.events.add('api_failure',json)
            }
            })
        end

        def observe
            @lingr.request('/event/observe', {
                "session" => @lingr.session_id,
                "counter" => @lingr.counter
            }, {
                "observe" => true,
                "success" => lambda{|json,lingr|
                @lingr.counter = [json["counter"],@lingr.counter].max unless json["counter"].nil?
                @lingr.events.add('observe_complete', json)
                @lingr.c_error = 0
                unless json["events"].nil?
                    ary = []
                    json["events"].each do |m|
                        unless m["message"].nil?
                            tmp = Message.new(
                                :timestamp => Time.parse(m["message"]["timestamp"]),
                                :icon_url => m["message"]["icon_url"],
                                :nickname => m["message"]["nickname"],
                                :text => m["message"]["text"],
                                :username => m["message"]["speaker_id"],
                                :room => m["message"]["room"]
                            )
                            ary << tmp
                        end
                    end
                    @lingr.events.add('new_message',ary) if ary.length > 0
                    ary2 = []
                    json["events"].each do |m|
                        if m["message"].nil?
                            n = m["offline"] if m["online"].nil?
                            n = m["online"] if m["offline"].nil?

                            tmp = Message.new(
                                :timestamp => Time.parse(n["timestamp"]),
                                :icon_url => n["icon_url"],
                                :nickname => n["nickname"],
                                :username => n["username"],
                                :text => n["text"],
                                :room => n["room"],
                                :presence => m["offline"].nil?
                            )
                            ary2 << tmp
                        end
                    end
                    @lingr.events.add('status_changed',ary2) if ary2.length > 0
                end
                lingr.observe_thread = Thread.new{ lingr.room.observe }
                lingr.observe_thread.join
            },
                "failure" => lambda{|json,lingr|
                lingr.events.add('observe_failure', json)
                lingr.c_error += 1
                Thread.new{ sleep 2**lingr.c_error; lingr.room.observe }.join if lingr.booted
            }
            })

        end
    end
    class Session
        def initialize(lingr)
            @lingr = lingr
            @presence = nil
            @username = nil
            if @lingr.params[:user].nil? || @lingr.params[:password].nil?
                raise ArgumentError,"params required user/pass"
            end
        end

        def start
            puts "debug: session.start" if @lingr.debug
            if @lingr.session_id.nil? 
                puts "debug: session create" if @lingr.debug
                params = {}
                params["user"] = @lingr.params[:user]
                params["password"] = @lingr.params[:password]
                @lingr.request('/session/create', params, {
                    "success" => lambda{|json,lingr|
                    puts "debug: session_create/success" if @lingr.debug
                    lingr.session_id = json["session"]
                    lingr.public_session_id = json["public_id"]
                    lingr.nickname = json["nickname"]
                    lingr.session.presence = json["presence"]
                    lingr.session.username = json["user"]["username"] unless json["user"].nil?
                    lingr.events.add('session_created',json)
                }
                })
            else
                @lingr.request('/session/verify', {"session"=>@lingr.session_id}, {
                    "success" => lambda{|json,lingr|
                    lingr.public_session_id = json["public_id"]
                    lingr.nickname = json["nickname"]
                    lingr.session.presence = json["presence"]
                    lingr.session.username = json["user"]["username"] unless json["user"].nil?
                    lingr.events.add('session_verified',json)
                },
                    "failture" => lambda{|json,lingr|
                    lingr.session_id = nil
                    lingr.public_session_id = nil
                    lingr.nickname = nil
                    lingr.session.presence = nil
                    lingr.session.username = nil
                    lingr.session.start
                }
                })
            end
        end

        def end
            unless @lingr.session_id.nil?
                @lingr.request('/session/destroy', {"session"=>@lingr.session_id},{
                    "success" => lambda{|json,lingr|
                        lingr.session_id = nil
                        lingr.public_session_id = nil
                        lingr.session.username = nil
                        lingr.session.presence = nil
                        lingr.nickname = nil
                        lingr.events.add('session_destroyed',json)
                    },
                    "failure" => lambda{|json,lingr|
                        lingr.session_id = nil
                        lingr.public_session_id = nil
                        lingr.session.username = nil
                        lingr.session.presence = nil
                        lingr.nickname = nil
                        lingr.events.add('api_failure',json);
                    }
                })
            end
        end

        def set_presence(presence,nickname=nil)
            nickname = @lingr.nickname if nickname.nil?
            @lingr.request('/session/set_presence', {
                    "session" => @lingr.session_id,
                    "nickname" => nickname,
                    "presence" => presence
            },{
                    "success" => lambda{|json,lingr|
                        if json["presence"] == 'online'
                            lingr.nickname = json["nickname"]
                            lingr.session.presence = 'online'
                        elsif json["presence"] == 'offline'
                            lingr.nickname = nil
                            lingr.session.presence = 'offline'
                        end
                        lingr.events.add('set_presence_complete',json)
                    },
                    "failure" => lambda{|json,lingr| lingr.events.add('api_failure',json) }
            })
        end
        attr_accessor :presence,:username
    end

    class User
        def initialize(lingr)
            @lingr = lingr
            @rooms = nil
        end

        def get_rooms
            @lingr.request('/user/get_rooms',{
                    "session" => @lingr.session_id
            },{
                    "success" => lambda{|json,lingr|
                        @lingr.user.rooms = json["rooms"]
                        @lingr.events.add('get_rooms_complete',json)
                    },
                    "failure" => lambda{|json,lingr| lingr.events.add('api_failure',json) }
        })
        end
        attr_accessor :rooms
    end
    
    class Message
        def initialize(hash = {})
            @timestamp = hash[:timestamp] || nil
            @text = hash[:text] || nil
            @presence = hash[:presence]
            @presence = true if @presence.nil?
            if hash[:user].nil?
                @user = Member.new(
                    :nickname => hash[:nickname],
                    :username => hash[:username],
                    :icon_url => hash[:icon_url],
                    :presence => hash[:presence]
                )
            else
                @user = hash[:user]
            end
        end
        attr_reader :timestamp,:text,:user
    end

    class Member
        def initialize(hash = {})
            @nickname = hash[:nickname] || nil
            @username = hash[:username] || nil
            @icon_url = hash[:icon_url] || nil
            @presence = hash[:presence]
            @presence = true if @member.nil?
            @owner = hash[:owner] || nil
        end
        attr_reader :nickname,:username,:icon_url,:presence,:owner
    end

    class Room
        def initialize(hash)
            @my_public = hash[:public] || nil
            @name = hash[:name] || nil
            @id = hash[:id] || nil
            @description = hash[:description] || nil
            @members = hash[:members] || []
            @messages = hash[:messages] || []
        end
        def public?;@my_public;end
        attr_reader :name,:id,:description,:members,:messages
    end

    attr_reader :params,:session,:room,:user,:events
    attr_accessor :session_id,:debug,:nickname,:public_session_id,:counter,:booting,:c_error,:booted,:rooms,:observe_thread
end

#--------------------------------------
module WebAPI
  # = Simple JSON parser & builder
  # Author::  Chihiro Ito
  # Support:: http://groups.google.com/group/webos-goodies/
  class JsonParser
    RUBY19             = RUBY_VERSION >= '1.9.0'
    Debug              = false
    Name               = 'WebAPI::JsonParser'
    ERR_IllegalSyntax  = "[#{Name}] Syntax error"
    ERR_IllegalUnicode = "[#{Name}] Illegal unicode sequence"
    StringRegex = /\s*"((?:\\.|[^"\\])*)"/n
    ValueRegex  = /\s*(?:
		(true)|(false)|(null)|            # 1:true, 2:false, 3:null
		(?:\"((?:\\.|[^\"\\])*)\")|       # 4:String
		([-+]?\d+\.\d+(?:[eE][-+]?\d+)?)| # 5:Float
		([-+]?\d+)|                       # 6:Integer
		(\{)|(\[))/xn                     # 7:Hash, 8:Array
    def initialize(options = {})
      @default_validation    = options.has_key?(:validation)    ? options[:validation]    : true
      @default_surrogate     = options.has_key?(:surrogate)     ? options[:surrogate]     : true
      @default_malformed_chr = options.has_key?(:malformed_chr) ? options[:malformed_chr] : nil
    end
    def parse(str, options = {})
      @enable_validation = options.has_key?(:validation)    ? options[:validation]    : @default_validation
      @enable_surrogate  = options.has_key?(:surrogate)     ? options[:surrogate]     : @default_surrogate
      @malformed_chr     = options.has_key?(:malformed_chr) ? options[:malformed_chr] : @default_malformed_chr
      @malformed_chr = @malformed_chr[0].ord if String === @malformed_chr
      if RUBY19
        str = (str.encode('UTF-8') rescue str.dup)
        if @enable_validation && !@malformed_chr
          raise err_msg(ERR_IllegalUnicode) unless str.valid_encoding?
          @enable_validation = false
        end
        str.force_encoding('ASCII-8BIT')
      end
      @scanner = StringScanner.new(str)
      obj = case get_symbol[0]
            when ?{ then parse_hash
            when ?[ then parse_array
            else         raise err_msg(ERR_IllegalSyntax)
            end
      @scanner = nil
      obj
    end
    private #---------------------------------------------------------
    def validate_string(str, malformed_chr = nil)
      code  = 0
      rest  = 0
      range = nil
      ucs   = []
      str.each_byte do |c|
        if rest <= 0
          case c
          when 0x01..0x7f then rest = 0 ; ucs << c
          when 0xc0..0xdf then rest = 1 ; code = c & 0x1f ; range = 0x00080..0x0007ff
          when 0xe0..0xef then rest = 2 ; code = c & 0x0f ; range = 0x00800..0x00ffff
          when 0xf0..0xf7 then rest = 3 ; code = c & 0x07 ; range = 0x10000..0x10ffff
          else                 ucs << handle_malformed_chr(malformed_chr)
          end
        elsif (0x80..0xbf) === c
          code = (code << 6) | (c & 0x3f)
          if (rest -= 1) <= 0
            if !(range === code) || (0xd800..0xdfff) === code
              code = handle_malformed_chr(malformed_chr)
            end
            ucs << code
          end
        else
          ucs << handle_malformed_chr(malformed_chr)
          rest = 0
        end
      end
      ucs << handle_malformed_chr(malformed_chr) if rest > 0
      ucs.pack('U*')
    end
    def handle_malformed_chr(chr)
      raise err_msg(ERR_IllegalUnicode) unless chr
      chr
    end
    def err_msg(err)
      err + (Debug ? " #{@scanner.string[[0, @scanner.pos - 8].max,16].inspect}" : "")
    end
    def unescape_string(str)
      str = str.gsub(/\\(["\\\/bfnrt])/n) do
        $1.tr('"\\/bfnrt', "\"\\/\b\f\n\r\t")
      end.gsub(/(\\u[0-9a-fA-F]{4})+/n) do |matched|
        seq = matched.scan(/\\u([0-9a-fA-F]{4})/n).flatten.map { |c| c.hex }
        if @enable_surrogate
          seq.each_index do |index|
            if seq[index] && (0xd800..0xdbff) === seq[index]
              n = index + 1
              raise err_msg(ERR_IllegalUnicode) unless seq[n] && 0xdc00..0xdfff === seq[n]
              seq[index] = 0x10000 + ((seq[index] & 0x03ff) << 10) + (seq[n] & 0x03ff)
              seq[n] = nil
            end
          end.compact!
        end
        seq.pack('U*')
      end
      str = validate_string(str, @malformed_chr) if @enable_validation
      RUBY19 ? str.force_encoding('UTF-8') : str
    end
    def get_symbol
      raise err_msg(ERR_IllegalSyntax) unless @scanner.scan(/\s*(.)/n)
      @scanner[1]
    end
    def peek_symbol
      @scanner.match?(/\s*(.)/n) ? @scanner[1] : nil
    end
    def parse_string
      raise err_msg(ERR_IllegalSyntax) unless @scanner.scan(StringRegex)
      unescape_string(@scanner[1])
    end
    def parse_value
      raise err_msg(ERR_IllegalSyntax) unless @scanner.scan(ValueRegex)
      case
      when @scanner[1] then true
      when @scanner[2] then false
      when @scanner[3] then nil
      when @scanner[4] then unescape_string(@scanner[4])
      when @scanner[5] then @scanner[5].to_f
      when @scanner[6] then @scanner[6].to_i
      when @scanner[7] then parse_hash
      when @scanner[8] then parse_array
      else                  raise err_msg(ERR_IllegalSyntax)
      end
    end
    def parse_hash
      obj = {}
      if peek_symbol[0] == ?} then get_symbol ; return obj ; end
      while true
        index = parse_string
        raise err_msg(ERR_IllegalSyntax) unless get_symbol[0] == ?:
        value = parse_value
        obj[index] = value
        case get_symbol[0]
        when ?} then return obj
        when ?, then next
        else         raise err_msg(ERR_IllegalSyntax)
        end
      end
    end
    def parse_array
      obj = []
      if peek_symbol[0] == ?] then get_symbol ; return obj ; end
      while true
        obj << parse_value
        case get_symbol[0]
        when ?] then return obj
        when ?, then next
        else         raise err_msg(ERR_IllegalSyntax)
        end
      end
    end
  end
end
