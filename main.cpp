#include "e32if.h"

#include <iostream>
#include <string>

int main(int argc, const char **argv)
{
	E32If e32if;

	try
	{
		e32if.run(argc, argv);
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

	std::cout << e32if.get();

	return(0);
}
