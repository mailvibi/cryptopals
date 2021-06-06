#include <iostream>
#include <cstddef>
#include <optional>
#include <vector>

std::optional<std::vector<std::byte>> myfunc(int j)
{
	if (j) 
		return std::vector<std::byte> {std::byte(3)}; 
	else 
		return std::nullopt;
}

int main(void)
{
	if (auto i = myfunc(1); i) {
		auto k = i.value();
		std::cout << std::to_integer<int>(i.value()[0]) << std::endl;
	} else {
		std::cout << "Invalid value myfunc(1)" << std::endl;
	}
 	
	if (auto i = myfunc(0); i) {
		std::cout << std::to_integer<int>((i.value())[0]);
	} else {
		std::cout << "Invalid value myfunc(0)" << std::endl;
	}
 	return 0;
}

