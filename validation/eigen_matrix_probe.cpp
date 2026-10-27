#if defined(TEST_MPC)
#include <boost/multiprecision/mpc.hpp>
using scalar = boost::multiprecision::mpc_complex;
#elif defined(TEST_MPFR)
#include <boost/multiprecision/mpfr.hpp>
using scalar = boost::multiprecision::mpfr_float;
#elif defined(TEST_GMP)
#include <boost/multiprecision/gmp.hpp>
using scalar = boost::multiprecision::mpf_float;
#else
#include <boost/multiprecision/cpp_bin_float.hpp>
using scalar = boost::multiprecision::cpp_bin_float_50;
#endif
#include <boost/multiprecision/eigen.hpp>
#include <sstream>

int main()
{
    Eigen::Matrix<scalar, 1, 1> value;
    value(0, 0) = scalar(1);
    std::ostringstream output;
    output << value;
    return output.str().empty();
}
