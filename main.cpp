#include "e32if.h"

#include <iostream>
#include <string>

int main(int argc, const char **argv)
{
	try
	{
		E32If(argc, argv);
	}
	catch(const std::string &e)
	{
		std::cerr << e << std::endl;
		return(-1);
	}
	catch(...)
	{
		std::cerr << "unknown exception" << std::endl;
		return(-1);
	}

	return(0);
}
