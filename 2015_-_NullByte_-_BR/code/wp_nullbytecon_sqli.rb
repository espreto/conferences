##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Title SQL Injection Scanner',
      'Description' => %q{
      This module attempts to exploit a...
      },
      'Author'       =>
        [
          'Roberto Soares Espreto <robertoespreto[at]com.br>' # Metasploit Module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'WPVDB', '0000' ]
        ],
      'DisclosureDate' => 'Nov 05 2015'))
  end

  def run_host(ip)
    sqli = ""

    vprint_status("#{peer} - Checking host")

    res = send_request_cgi(
      'uri'       => wordpress_url_backend,
      'vars_get'  => {
        'bla'     => sqli
      }
    )

    if res && res.code == 200 && res.body
      print_good("#{peer} - Vulnerable to SQL injection")
    else
      print_error("#{peer} - Server did not respond in an expected way")
    end
  end
end
