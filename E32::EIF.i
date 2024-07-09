%module "E32::EIF"

%include std_string.i
%include std_vector.i
%include exception.i

namespace std {
	%template(vector_string) vector<string>;
};

%{
#include <iostream>
#include <string>
#include "e32if.h"
%}

%exception
{
	try
	{
		$action
	}
	catch(const std::string &e)
	{
		std::cerr << "E32::EIF: string exception: " << e << std::endl;
		SWIG_exception(SWIG_RuntimeError, "abort");
	}
	catch(...)
	{
		std::cerr << "unknown exception caught" << std::endl;
		SWIG_exception(SWIG_RuntimeError, "E32::EIF: generic exception\nabort");
	}
}

%include "e32if.h"
