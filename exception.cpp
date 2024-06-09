#include "exception.h"

e32if_exception::e32if_exception(const std::string &what)
		:
	what_string(what)
{
}

e32if_exception::e32if_exception(const char *what)
		:
	what_string(what)
{
}

e32if_exception::e32if_exception(const boost::format &what)
		:
	what_string(what.str())
{
}

const char *e32if_exception::what() const noexcept
{
	return(what_string.c_str());
}

hard_exception::hard_exception(const std::string &what)
		:
	e32if_exception(what)
{
}

hard_exception::hard_exception(const char *what)
		:
	e32if_exception(what)
{
}

hard_exception::hard_exception(const boost::format &what)
		:
	e32if_exception(what)
{
}

transient_exception::transient_exception(const std::string &what)
		:
	e32if_exception(what)
{
}

transient_exception::transient_exception(const char *what)
		:
	e32if_exception(what)
{
}

transient_exception::transient_exception(const boost::format &what)
		:
	e32if_exception(what)
{
}
