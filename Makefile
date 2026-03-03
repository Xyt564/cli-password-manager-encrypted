CXX      = g++
CXXFLAGS = -std=c++17 -O2 -Wall -I. -I/usr/include/node
LDFLAGS  = -L/usr/lib/x86_64-linux-gnu -l:libcrypto.so.3 -l:libargon2.so.1
TARGET   = pwmgr
SRC      = main.cpp

.PHONY: all clean install standard

all: $(TARGET)

$(TARGET): $(SRC) argon2_min.h
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)
	@echo "Built: ./$(TARGET)"

# Standard systems with libssl-dev + libargon2-dev:
#   sudo apt install libssl-dev libargon2-dev
standard: $(SRC) argon2_min.h
	$(CXX) $(CXXFLAGS) $< -o $(TARGET) -lcrypto -largon2
	@echo "Built: ./$(TARGET)"

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/$(TARGET)
