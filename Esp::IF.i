%module "Esp::IF"

%include <std_string.i>
%include <exception.i>

%{
#include <iostream>
#include "espif.h"
#include "espifconfig.h"
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
		std::cerr << "Esp::IF: hard exception: " << e.what() << std::endl;
		die("abort");
	}
	catch(const transient_exception &e)
	{
		std::cerr << "Esp::IF: transient exception: " << e.what() << std::endl;
		die("abort");
	}
	catch(const espif_exception &e)
	{
		std::cerr << "Esp::IF: unspecified exception: " << e.what() << std::endl;
		die("abort");
	}
	catch(const std::exception &e)
	{
		std::cerr << "Esp::IF: STD exception: " << e.what() << std::endl;
		die("abort");
	}
	catch(const std::string &e)
	{
		std::cerr << "Esp::IF: string exception: " << e << std::endl;
		die("abort");
	}
	catch(const char *e)
	{
		std::cerr << "Esp::IF: charp exception: " << e << std::endl;
		die("abort");
	}
	catch(...)
	{
		die("Esp::IF: generic exception\nabort");
	}
}

%include "espif.h"
%include "espifconfig.h"

%perlcode %{
	sub new_EspifConfig($)
	{
		my($config) = @_;
		my($key, $value, $espifconfig);

		$espifconfig = new Esp::IF::EspifConfig;

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

				$espifconfig->{"transport"} = $transport_type;
			}
			else
			{
				$espifconfig->{$key} = $value;
			}
		}

		return($espifconfig);
	}
%}
