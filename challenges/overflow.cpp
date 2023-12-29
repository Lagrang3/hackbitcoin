#include <cstdint>
#include <iostream>
#include <iomanip>
#include <vector>
#include <limits>

constexpr std::int64_t COIN  = 100'000'000;
constexpr std::int64_t MAX_MONEY = 21*COIN;

constexpr std::int64_t MAX_INT = std::numeric_limits<std::int64_t>::max();

template<class T>
bool check_transaction(const std::vector<T>& in, const std::vector<T>& out)
{
	T sum_in{0}, sum_out{0};
	
	for(auto i: in)
		sum_in += i;
	for(auto o: out)
		sum_out += o;
	
	return sum_in >= sum_out;
}

template<class T>
T sum_vector(const std::vector<T>& v)
{
	T s = 0;
	for(auto x: v) s += x;
	return s;
}
template<class T>
void print_vector(std::ostream& os, const std::vector<T>& v)
{
	for(auto x: v) os << x << ", ";
	os << '\n';
}

template<class T>
void print_transaction(std::ostream &os, const std::vector<T>& in, const std::vector<T>& out)
{
	os << "inputs: ";
	print_vector(os, in);
	os << "output: ";
	print_vector(os, out);
	T fees = sum_vector(in) - sum_vector(out);
	os << "fees: " << fees << "\n";
	os << "check transaction: " << std::boolalpha << check_transaction(in, out) << "\n";
}

int main()
{
	// read any value from input
	// x: the input
	// y: the desired output
	std::int64_t x, y; std::cin >> x >> y;
	
	std::vector<std::int64_t> in{x};
	
	// let x be the only input,
	// let y be the desired output
	// let r1, r2 be two change outputs
	// let M = 2^64 (the modulo of arithmetic operations)
	// let m = 2^63 - 1 (the maximum value int can be)
	// 
	// overflow means that
	// x + M = y + r1 + r2 + fee
	// 
	// we choose:
	// 	y + r1 = m
	// 	r2 = m
	// 
	// hence
	// 	r1 = m - y
	// 	r2 = m
	// 	fee = x + 2
	// 
	// this constructed solution satisfies the equation so that for any
	// given input x, we can construct any desired output y.
	
	std::int64_t r2 = MAX_INT;
	std::int64_t r1 = MAX_INT - y;
	std::vector<std::int64_t> out{y, r1, r2};
	
	print_transaction(std::cout, in, out);
	
	return 0;
}
