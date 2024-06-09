%module "E32::EIF"

%include <std_string.i>
%include <exception.i>

%{
#include <iostream>
#include "e32if.h"
#include "e32ifconfig.h"
#include "exception.h"
%}

%include "exception.h"

%exception
{
	try
	{
		$action
	}
	catch(const hard_exception &e)
	{
		std::cerr << "E32::EIF: hard exception: " << e.what() << std::endl;
		die("abort");
	}
	catch(const transient_exception &e)
	{
		std::cerr << "E32::EIF: transient exception: " << e.what() << std::endl;
		die("abort");
	}
	catch(const e32if_exception &e)
	{
		std::cerr << "E32::EIF: unspecified exception: " << e.what() << std::endl;
		die("abort");
	}
	catch(const std::exception &e)
	{
		std::cerr << "E32::EIF: STD exception: " << e.what() << std::endl;
		die("abort");
	}
	catch(const std::string &e)
	{
		std::cerr << "E32::EIF: string exception: " << e << std::endl;
		die("abort");
	}
	catch(const char *e)
	{
		std::cerr << "E32::EIF: charp exception: " << e << std::endl;
		die("abort");
	}
	catch(...)
	{
		die("E32::EIF: generic exception\nabort");
	}
}

%include "e32if.h"
%include "e32ifconfig.h"

%perlcode %{
	sub new_E32IfConfig($)
	{
		my($config) = @_;
		my($key, $value, $e32ifconfig);

		$e32ifconfig = new E32::EIF::E32IfConfig;

		foreach $key (keys(%$config))
		{
			$value = $$config{$key};

			if($key eq "transport")
			{
				# transport_none = 0,
				# transport_tcp_ip = 1,
				# transport_udp_ip = 2,
				# transport_bluetooth = 3,

				my($transport_type);

				if(($value eq "bt") || ($value eq "bluetooth"))
				{
					$transport_type = 3;
				}
				elsif($value eq "tcp")
				{
					$transport_type = 1;
				}
				elsif($value eq "udp")
				{
					$transport_type = 2;
				}
				else
				{
					die("unknown transport, use bluetooth/bt, udp or ip");
				}

				$e32ifconfig->{"transport"} = $transport_type;
			}
			else
			{
				$e32ifconfig->{$key} = $value;
			}
		}

		return($e32ifconfig);
	}
%}
