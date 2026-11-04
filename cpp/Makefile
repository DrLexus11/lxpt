# The C++ tests. `make test` builds them in C++11 and C++17 under ASan and
# UBSan and runs both against the shared fixtures: the wire fixture with a
# 10^5-input fuzz run, then the floor and relay fixtures, checking that no core
# call allocates. `make embedded` builds the headers with -fno-exceptions
# -fno-rtti.
#
#   make test CXX=clang++
#   make test CROSSCHECK=../out/cpp.txt

CXX ?= g++
FIXTURE ?= ../fixtures/lxpt_wire_v1.json
FLOOR_FIXTURE ?= ../fixtures/lxpt_floor_v1.json
RELAY_FIXTURE ?= ../fixtures/lxpt_relay_v1.json
FUZZ ?= 100000
CROSSCHECK ?= -
OBJ := build
WARN = -Wall -Wextra -Werror -pedantic -Wshadow -Wconversion -Wno-sign-conversion
SAN = -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
HEADERS = $(wildcard include/lxpt/*.hpp)

.PHONY: test embedded clean

test: $(OBJ)/test_cpp11 $(OBJ)/test_cpp17 $(OBJ)/cores_cpp11 $(OBJ)/cores_cpp17 embedded
	$(OBJ)/test_cpp11 $(FIXTURE) $(CROSSCHECK) $(FUZZ)
	$(OBJ)/test_cpp17 $(FIXTURE) - $(FUZZ)
	$(OBJ)/cores_cpp11 $(FLOOR_FIXTURE) $(RELAY_FIXTURE) $(CROSSCHECK)
	$(OBJ)/cores_cpp17 $(FLOOR_FIXTURE) $(RELAY_FIXTURE) -

$(OBJ)/test_cpp11: tests/test_lxpt.cpp tests/json.hpp $(HEADERS)
	@mkdir -p $(OBJ)
	$(CXX) -std=c++11 -O1 -g $(WARN) $(SAN) $< -o $@

$(OBJ)/test_cpp17: tests/test_lxpt.cpp tests/json.hpp $(HEADERS)
	@mkdir -p $(OBJ)
	$(CXX) -std=c++17 -O1 -g $(WARN) $(SAN) $< -o $@

$(OBJ)/cores_cpp11: tests/test_cores.cpp tests/json.hpp $(HEADERS)
	@mkdir -p $(OBJ)
	$(CXX) -std=c++11 -O1 -g $(WARN) $(SAN) $< -o $@

$(OBJ)/cores_cpp17: tests/test_cores.cpp tests/json.hpp $(HEADERS)
	@mkdir -p $(OBJ)
	$(CXX) -std=c++17 -O1 -g $(WARN) $(SAN) $< -o $@

embedded: tests/embedded_build.cpp $(HEADERS)
	@mkdir -p $(OBJ)
	$(CXX) -std=c++11 -Os $(WARN) -fno-exceptions -fno-rtti $< -o $(OBJ)/embedded_build
	$(OBJ)/embedded_build

clean:
	rm -rf $(OBJ)
