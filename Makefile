# Compiler and flags
CXX = g++
CXXFLAGS = -I/usr/local/openssl/include -Itoolkit
LDFLAGS = -L/usr/local/openssl/lib -lssl -lcrypto
TARGET = main
SRCS = main.cpp toolkit/rsa.cpp toolkit/aes.cpp toolkit/sha256.cpp
OBJS = $(SRCS:.cpp=.o)

# Default target
all: $(TARGET)

# Rule to link the object files and create the executable
$(TARGET): $(OBJS)
	$(CXX) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Rule to compile the source files into object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean rule to remove generated files
clean:
	rm -f $(TARGET) $(OBJS)

# Phony targets
.PHONY: all clean
